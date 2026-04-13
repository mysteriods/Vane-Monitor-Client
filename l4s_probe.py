"""
L4S (Low Latency, Low Loss, Scalable Throughput) probe module.

Synthetic end-to-end test that:
  1. Detects whether the OS can mark outgoing packets as ECT(1) — the L4S
     "VIP pass" for a DualQ Coupled AQM low-latency queue.
  2. Compares ECT(1) vs ECT(0) TCP-connect RTT and loss rate to infer DualQ
     queue separation and to flag ISP bleaching (ECT bit zeroing).
  3. Measures the IETF "responsiveness" metric:
       RPM = 60,000 / working_latency_ms
     as defined in draft-ietf-ippm-responsiveness / RFC 9330.
  4. Reports the 99th-percentile latency (sojourn proxy) under a sustained
     10-second multi-stream load.

Limitations
-----------
Confirming that the *network* preserved our outgoing ECT(1) bits end-to-end
requires either a cooperating L4S reflector or raw-socket (root/CAP_NET_RAW)
privileges — neither of which are assumed here.  We instead infer ECN path
status from:

  * getsockopt() round-trip: confirms the OS actually stamps the TOS byte.
  * Loss-rate disparity: ECT(1) loss >> ECT(0) loss suggests the ISP is
    filtering or bleaching ECT-marked traffic.

Windows note
------------
Windows 10/11 user-mode sockets zero IP_TOS by default.  The OS ECN check
will return False and ecn_path_status will be "Not-Supported".  To enable:

  • Elevated process + raw sockets (SOCK_RAW), or
  • PowerShell:  New-NetQosPolicy -Name L4S -DSCPAction 1 -NetworkProfile All

Usage
-----
    from client.l4s_probe import run_l4s_probe

    result = run_l4s_probe(target_host="1.1.1.1")
    # result keys: l4s_supported, ecn_path_status, working_latency_ms,
    #              rpm_score, p99_latency_ms, dualq_detected, ...
"""

import platform
import socket
import statistics
import threading
import time
import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── ECN field values (low 2 bits of IP TOS / IPv6 Traffic Class) ──────────────
ECN_NON_ECT: int = 0x00   # Not ECN-capable transport
ECN_ECT1:    int = 0x01   # L4S scalable-CC identifier  (RFC 9330)
ECN_ECT0:    int = 0x02   # Classic ECN-capable transport (RFC 3168)
ECN_CE:      int = 0x03   # Congestion Experienced

# ── Socket option codes (guard against missing platform attributes) ─────────────
_IP_TOS:       int = getattr(socket, "IP_TOS",       1)
_IPV6_TCLASS:  int = getattr(socket, "IPV6_TCLASS",  67)
_IPPROTO_IPV6: int = getattr(socket, "IPPROTO_IPV6", 41)

# ── Tuning knobs ───────────────────────────────────────────────────────────────
_DEFAULT_HOST:       str   = "1.1.1.1"   # Cloudflare anycast; fast & global
_DEFAULT_PORT:       int   = 80
_ECN_PROBE_COUNT:    int   = 20          # TCP-connect probes per ECN class
_ECN_PROBE_TIMEOUT:  float = 1.5         # per-connect timeout (seconds)
_ECN_BLEACH_DELTA:   float = 0.10        # ≥10 pp extra ECT(1) loss → Bleached
_DUALQ_ADV_MS:       float = 5.0         # ECT(0)−ECT(1) RTT threshold for DualQ
_RPM_DURATION_SEC:   int   = 10          # saturation-test window
_RPM_PROBE_INTERVAL: float = 0.05        # 50 ms between probe connects
_RPM_LOAD_STREAMS:   int   = 4           # parallel load-generating TCP streams
_LOAD_TIMEOUT:       float = 3.0         # connect timeout for load workers
_PROBE_TIMEOUT:      float = 2.0         # connect timeout for probe worker


class L4SProbe:
    """
    Measures end-to-end L4S / ECN path support and IETF responsiveness (RPM).

    Parameters
    ----------
    target_host  : Hostname or IPv4 address to probe.  Must be reachable over
                   TCP on *target_port* (default 80).
    target_port  : TCP port used for SYN-RTT probing.
    rpm_duration : Duration in seconds of the RPM saturation window.
    load_streams : Parallel HTTP streams for path saturation.
    """

    def __init__(
        self,
        target_host:  str = _DEFAULT_HOST,
        target_port:  int = _DEFAULT_PORT,
        rpm_duration: int = _RPM_DURATION_SEC,
        load_streams: int = _RPM_LOAD_STREAMS,
    ) -> None:
        self.target_host  = target_host
        self.target_port  = target_port
        self.rpm_duration = rpm_duration
        self.load_streams = load_streams
        self._os          = platform.system().lower()
        self._ipv4_addr   = self._resolve(target_host)

    # ─── Public entry point ────────────────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        """
        Execute the full L4S probe suite.

        Returns
        -------
        dict
            test_type          : "l4s_probe"
            target             : str
            timestamp          : ISO-8601 UTC
            success            : bool
            l4s_supported      : bool — OS marks ECT(1), path is not bleached,
                                 and RPM data was collected.
            ecn_path_status    : "Preserved" | "Bleached" | "Not-Supported"
            dualq_detected     : bool | None — ECT(0)−ECT(1) RTT ≥ 5 ms
                                 indicates a DualQ low-latency queue.
            working_latency_ms : float | None — median TCP SYN-RTT under load
            rpm_score          : int   | None — 60,000 / working_latency_ms
            p99_latency_ms     : float | None — 99th-pct RTT under load
            ect1_rtt_ms        : float | None — baseline RTT, ECT(1)-marked flows
            ect0_rtt_ms        : float | None — baseline RTT, ECT(0)-marked flows
            ect1_loss_pct      : float | None — % ECT(1) probes that timed out
            ect0_loss_pct      : float | None — % ECT(0) probes that timed out
            fallback_to_classic: bool — True when the path appears L4S-unfriendly
                                 and the RPM test was run with Classic ECN instead.
            os_ecn_support     : bool — OS honoured IP_TOS = ECT(1)
            error              : str | None
        """
        ts = datetime.now(timezone.utc).isoformat()
        out: Dict[str, Any] = {
            "test_type":           "l4s_probe",
            "target":              self.target_host,
            "timestamp":           ts,
            "success":             False,
            "l4s_supported":       False,
            "ecn_path_status":     "Unknown",
            "dualq_detected":      None,
            "working_latency_ms":  None,
            "rpm_score":           None,
            "p99_latency_ms":      None,
            "ect1_rtt_ms":         None,
            "ect0_rtt_ms":         None,
            "ect1_loss_pct":       None,
            "ect0_loss_pct":       None,
            "fallback_to_classic": False,
            "os_ecn_support":      False,
            "error":               None,
        }

        if not self._ipv4_addr:
            out["error"] = f"Cannot resolve {self.target_host!r}"
            logger.warning("L4S probe: %s", out["error"])
            return out

        # ── 1. OS ECN capability ───────────────────────────────────────────
        os_ecn = self._check_os_ecn_support()
        out["os_ecn_support"] = os_ecn
        logger.debug("OS ECN support (IP_TOS=ECT1 honoured): %s", os_ecn)

        if not os_ecn:
            out["ecn_path_status"] = "Not-Supported"
            logger.info(
                "L4S probe: OS does not preserve IP_TOS=ECT(1) for user-mode "
                "sockets (Windows: needs elevation or Set-NetQosPolicy). "
                "Collecting RPM baseline with unmark traffic."
            )
            out.update(self._run_rpm_test(ECN_NON_ECT))
            out["success"] = out["working_latency_ms"] is not None
            return out

        # ── 2. ECT(1) and ECT(0) baseline probes — run in parallel ────────
        ect1_res: List[Optional[float]] = [None, None]
        ect0_res: List[Optional[float]] = [None, None]

        def _run_ect1() -> None:
            rtt, loss = self._ecn_probe(ECN_ECT1)
            ect1_res[0], ect1_res[1] = rtt, loss

        def _run_ect0() -> None:
            rtt, loss = self._ecn_probe(ECN_ECT0)
            ect0_res[0], ect0_res[1] = rtt, loss

        probe_timeout = _ECN_PROBE_COUNT * _ECN_PROBE_TIMEOUT + 2
        t1 = threading.Thread(target=_run_ect1, daemon=True, name="l4s-ect1-baseline")
        t0 = threading.Thread(target=_run_ect0, daemon=True, name="l4s-ect0-baseline")
        t1.start(); t0.start()
        t1.join(timeout=probe_timeout)
        t0.join(timeout=probe_timeout)

        ect1_rtt,  ect1_loss = ect1_res[0], ect1_res[1]
        ect0_rtt,  ect0_loss = ect0_res[0], ect0_res[1]

        out["ect1_rtt_ms"]   = _r2(ect1_rtt)
        out["ect0_rtt_ms"]   = _r2(ect0_rtt)
        out["ect1_loss_pct"] = _r2(ect1_loss * 100) if ect1_loss is not None else None
        out["ect0_loss_pct"] = _r2(ect0_loss * 100) if ect0_loss is not None else None

        logger.debug(
            "Baseline ECT(1): rtt=%.1f ms loss=%.1f%% | "
            "ECT(0): rtt=%.1f ms loss=%.1f%%",
            ect1_rtt or 0, (ect1_loss or 0) * 100,
            ect0_rtt or 0, (ect0_loss or 0) * 100,
        )

        # ── 3. ECN path status ─────────────────────────────────────────────
        ecn_status = self._determine_ecn_status(ect1_loss, ect0_loss)
        out["ecn_path_status"] = ecn_status

        # ── 4. Fallback: L4S-unfriendly path ──────────────────────────────
        fallback = ecn_status == "Bleached"
        out["fallback_to_classic"] = fallback
        if fallback:
            logger.warning(
                "L4S-unfriendly path detected — ECT(1) loss %.1f%% vs "
                "ECT(0) loss %.1f%%.  RPM test will use Classic ECN (ECT(0)).",
                (ect1_loss or 0) * 100, (ect0_loss or 0) * 100,
            )

        # ── 5. DualQ detection ─────────────────────────────────────────────
        if ect1_rtt is not None and ect0_rtt is not None:
            advantage_ms = ect0_rtt - ect1_rtt
            out["dualq_detected"] = advantage_ms >= _DUALQ_ADV_MS
            logger.debug(
                "DualQ: ECT(0)−ECT(1) advantage = %.1f ms "
                "(threshold %.0f ms) → %s",
                advantage_ms, _DUALQ_ADV_MS, out["dualq_detected"],
            )

        # ── 6. RPM responsiveness test (10-second saturation window) ───────
        rpm_mark = ECN_ECT0 if fallback else ECN_ECT1
        out.update(self._run_rpm_test(rpm_mark))

        # ── 7. Overall L4S verdict ─────────────────────────────────────────
        out["l4s_supported"] = (
            os_ecn
            and ecn_status == "Preserved"
            and not fallback
            and out["working_latency_ms"] is not None
        )
        out["success"] = True

        logger.info(
            "L4S probe done — supported=%s ecn_status=%s dualq=%s "
            "working_lat=%.1f ms rpm=%s p99=%.1f ms",
            out["l4s_supported"],
            ecn_status,
            out["dualq_detected"],
            out["working_latency_ms"] or 0,
            out["rpm_score"],
            out["p99_latency_ms"] or 0,
        )
        return out

    # ─── OS ECN capability ─────────────────────────────────────────────────────

    def _check_os_ecn_support(self) -> bool:
        """
        Confirm the OS actually stamps IP_TOS = ECT(1) on outgoing packets.

        We write ECT(1) via ``setsockopt`` and immediately verify with
        ``getsockopt``.  Windows silently zeroes IP_TOS for user-mode sockets
        (the "ECT(1) Trap"), so ``getsockopt`` is the definitive check — not
        the absence of an ``OSError``.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.IPPROTO_IP, _IP_TOS, ECN_ECT1)
                actual = s.getsockopt(socket.IPPROTO_IP, _IP_TOS)
                return (actual & 0x03) == ECN_ECT1
        except OSError as exc:
            logger.debug("setsockopt(IP_TOS) rejected by OS: %s", exc)
            return False

    # ─── ECN-marked TCP-connect probes ─────────────────────────────────────────

    def _ecn_probe(
        self,
        ecn_mark: int,
        count: int = _ECN_PROBE_COUNT,
    ) -> Tuple[Optional[float], Optional[float]]:
        """
        Perform *count* TCP connects with *ecn_mark* stamped in IP_TOS.

        Returns
        -------
        (avg_rtt_ms, loss_fraction)
            avg_rtt_ms    : mean connect RTT in milliseconds, or None if all
                            probes timed out.
            loss_fraction : fraction [0.0–1.0] of probes that failed to connect.
        """
        rtts:     List[float] = []
        timeouts: int         = 0

        for _ in range(count):
            t0 = time.monotonic()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(_ECN_PROBE_TIMEOUT)
                    self._apply_tos(s, ecn_mark)
                    s.connect((self._ipv4_addr, self.target_port))
                rtts.append((time.monotonic() - t0) * 1_000)
            except (socket.timeout, OSError):
                timeouts += 1

        avg_rtt   = statistics.mean(rtts) if rtts else None
        loss_frac = timeouts / count
        return avg_rtt, loss_frac

    # ─── ECN path status inference ─────────────────────────────────────────────

    def _determine_ecn_status(
        self,
        ect1_loss: Optional[float],
        ect0_loss: Optional[float],
    ) -> str:
        """
        Infer ECN path status from loss-rate observations.

        Without a cooperating L4S reflector we cannot directly observe
        whether our outgoing ECT(1) bits were preserved by every hop.
        We use the following heuristic:

        Bleached
            ECT(1) loss rate exceeds ECT(0) loss by ≥ ``_ECN_BLEACH_DELTA``
            (default 10 percentage points).  The ISP is likely dropping or
            rate-limiting ECT-marked traffic — effectively ISP interference.
            Dashboard should surface this as "ISP Interference".

        Preserved (optimistic)
            OS confirms ECT(1) marking, and there is no significant loss
            disparity.  We cannot rule out transparent bit-zeroing (bleaching
            without packet loss), which requires a cooperating reflector to
            detect definitively.
        """
        if ect1_loss is None:
            return "Unknown"

        baseline = ect0_loss if ect0_loss is not None else 0.0
        if (ect1_loss - baseline) >= _ECN_BLEACH_DELTA:
            return "Bleached"

        return "Preserved"

    # ─── RPM / responsiveness test ─────────────────────────────────────────────

    def _run_rpm_test(self, ecn_mark: int) -> Dict[str, Any]:
        """
        IETF-style responsiveness test (draft-ietf-ippm-responsiveness).

        Architecture
        ------------
        Load workers (``self.load_streams`` threads)
            Each worker opens a persistent TCP connection and issues HTTP/1.0
            GET requests in a tight loop, keeping the forward path saturated.
            All sockets are marked with *ecn_mark* in IP_TOS.

        Probe worker (1 thread)
            Measures TCP SYN-ACK RTT (sojourn proxy) every
            ``_RPM_PROBE_INTERVAL`` seconds for ``self.rpm_duration`` seconds
            while the path is under load.

        Metric
        ------
        RPM = 60,000 / median_working_latency_ms

        A well-functioning L4S path maintains near-baseline SYN-RTT even at
        100% utilisation, because the DualQ AQM keeps the ECT(1) queue shallow.
        """
        stop_event  = threading.Event()
        probe_rtts: List[float] = []
        probe_lock  = threading.Lock()

        http_req = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {self.target_host}\r\n"
            f"User-Agent: VaneMonitor-L4S/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        # ── Load worker ────────────────────────────────────────────────────
        def _load_worker() -> None:
            while not stop_event.is_set():
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(_LOAD_TIMEOUT)
                        self._apply_tos(s, ecn_mark)
                        s.connect((self._ipv4_addr, self.target_port))
                        s.sendall(http_req)
                        s.settimeout(_LOAD_TIMEOUT)
                        while not stop_event.is_set():
                            chunk = s.recv(65_536)
                            if not chunk:
                                break   # server closed; reconnect
                except Exception:
                    pass   # network error — reconnect immediately

        # ── Probe worker ───────────────────────────────────────────────────
        def _probe_worker() -> None:
            deadline = time.monotonic() + self.rpm_duration
            while time.monotonic() < deadline:
                t0 = time.monotonic()
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(_PROBE_TIMEOUT)
                        self._apply_tos(s, ecn_mark)
                        s.connect((self._ipv4_addr, self.target_port))
                    with probe_lock:
                        probe_rtts.append((time.monotonic() - t0) * 1_000)
                except Exception:
                    pass
                time.sleep(_RPM_PROBE_INTERVAL)

        # ── Orchestrate ────────────────────────────────────────────────────
        load_threads = [
            threading.Thread(
                target=_load_worker, daemon=True, name=f"l4s-load-{i}"
            )
            for i in range(self.load_streams)
        ]
        probe_thread = threading.Thread(
            target=_probe_worker, daemon=True, name="l4s-probe"
        )

        for t in load_threads:
            t.start()
        probe_thread.start()
        probe_thread.join(timeout=self.rpm_duration + _PROBE_TIMEOUT + 2)
        stop_event.set()
        for t in load_threads:
            t.join(timeout=_LOAD_TIMEOUT + 1)

        with probe_lock:
            samples = list(probe_rtts)

        if not samples:
            logger.warning(
                "RPM test: no RTT samples collected from %s:%d",
                self.target_host, self.target_port,
            )
            return {"working_latency_ms": None, "rpm_score": None, "p99_latency_ms": None}

        median_ms = statistics.median(samples)
        p99_ms    = _percentile(samples, 99)
        rpm       = int(60_000 / median_ms) if median_ms > 0 else None

        logger.info(
            "RPM test: %d samples — median %.1f ms, p99 %.1f ms → RPM %s",
            len(samples), median_ms, p99_ms or 0, rpm,
        )
        return {
            "working_latency_ms": _r2(median_ms),
            "rpm_score":          rpm,
            "p99_latency_ms":     _r2(p99_ms),
        }

    # ─── Socket helpers ────────────────────────────────────────────────────────

    def _apply_tos(self, sock: socket.socket, ecn_mark: int) -> None:
        """
        Stamp the ECN field (low 2 bits) of IP_TOS / IPV6_TCLASS on *sock*,
        preserving any existing DSCP value in the upper 6 bits.

        Silently swallows ``OSError`` — the caller checks ``os_ecn_support``
        at the suite level; individual socket failures are non-fatal.

        IPv4 TOS byte layout:
            bits 7-2  DSCP (Differentiated Services Code Point)
            bits 1-0  ECN  (00=Non-ECT, 01=ECT1/L4S, 10=ECT0, 11=CE)
        """
        try:
            family = sock.family
            if family == socket.AF_INET:
                current = sock.getsockopt(socket.IPPROTO_IP, _IP_TOS)
                sock.setsockopt(
                    socket.IPPROTO_IP, _IP_TOS,
                    (current & 0xFC) | (ecn_mark & 0x03),
                )
            elif family == socket.AF_INET6:
                current = sock.getsockopt(_IPPROTO_IPV6, _IPV6_TCLASS)
                sock.setsockopt(
                    _IPPROTO_IPV6, _IPV6_TCLASS,
                    (current & 0xFC) | (ecn_mark & 0x03),
                )
        except OSError:
            pass

    @staticmethod
    def _resolve(host: str) -> Optional[str]:
        """Resolve *host* to an IPv4 address string, or return None."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None


# ── Module-level helpers ────────────────────────────────────────────────────────

def _percentile(data: List[float], pct: int) -> Optional[float]:
    """Return the *pct*-th percentile of *data*, or None if *data* is empty."""
    if not data:
        return None
    s   = sorted(data)
    idx = max(0, int(len(s) * pct / 100) - 1)
    return s[idx]


def _r2(v: Optional[float]) -> Optional[float]:
    """Round *v* to 2 decimal places, propagating None."""
    return round(v, 2) if v is not None else None


# ── Convenience wrapper ─────────────────────────────────────────────────────────

def run_l4s_probe(
    target_host:  str = _DEFAULT_HOST,
    target_port:  int = _DEFAULT_PORT,
    rpm_duration: int = _RPM_DURATION_SEC,
    load_streams: int = _RPM_LOAD_STREAMS,
) -> Dict[str, Any]:
    """
    Execute the full L4S probe suite and return a result dict.

    Parameters
    ----------
    target_host  : Far-end host (hostname or IPv4).  Must be reachable on TCP
                   *target_port*.  Default is ``1.1.1.1`` (Cloudflare anycast).
    target_port  : TCP port for SYN-RTT probing (default 80).
    rpm_duration : Saturation-test window in seconds (default 10).
    load_streams : Parallel TCP streams for path saturation (default 4).

    Returns
    -------
    dict
        See :meth:`L4SProbe.run` for the full schema.
    """
    return L4SProbe(
        target_host=target_host,
        target_port=target_port,
        rpm_duration=rpm_duration,
        load_streams=load_streams,
    ).run()
