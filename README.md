# Vane Monitor Client

This directory contains the standalone Vane Monitor client application.

The client runs scheduled network checks and sends results to a Vane Monitor server. It can be run directly with Python during development, or packaged into a standalone executable for distribution.

## Prerequisites

This project is a Python application, not a Node.js application.

You do not need Node.js, `npm`, or `yarn`.

Required:

- Python 3.9 or newer
- `pip` (usually included with Python)
- Git

Recommended:

- A virtual environment for local installation
- Network access to a reachable Vane Monitor server
- Administrator or root privileges only if your environment requires elevated permissions for some network checks

## Files in This Directory

- `main.py` - client entry point
- `client.py` - main client runtime
- `requirements.txt` - Python dependencies
- `VaneMonitorClient.spec` - PyInstaller build spec
- `offline_queue.py` - offline result queue handling
- `l4s_probe.py` - optional L4S probing support
- `asn_cache.json` - runtime ASN cache file

## Installation

### 1. Clone the repository

Replace the URL below with your public client repository URL:

```bash
git clone https://github.com/your-org/your-client-repo.git
cd your-client-repo/client
```

If this directory is the repository root in your public repo, use:

```bash
git clone https://github.com/your-org/your-client-repo.git
cd your-client-repo
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```bat
python -m venv .venv
.venv\Scripts\activate.bat
```

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Current dependencies include:

- `aioping` for enhanced ICMP ping support
- `pyinstaller` for building a standalone executable

## Configuration

The client uses `client_config.json` for runtime settings.

If the file is missing, empty, or still contains default placeholder values, the client will prompt you for setup information the first time it starts.

A typical configuration file looks like this:

```json
{
    "client_name": "",
    "server_url": "",
    "test_interval": 60,
    "verify_ssl": false,
    "enable_l4s_testing": true,
    "l4s_target": "1.1.1.1",
    "l4s_interval": 600
}
```

### Required fields

- `client_name`
  A unique name for this client device.
  Example: `office-laptop-01`

- `server_url`
  URL of your Vane Monitor server.
  Example: `https://monitor.example.com:5000`

### Common fields

- `test_interval`
  Interval in seconds between scheduled test runs.

- `verify_ssl`
  Set to `true` to validate the server TLS certificate.
  Set to `false` if you are using a self-signed certificate.

- `enable_l4s_testing`
  Enables the optional L4S probe.

- `l4s_target`
  Target host for the L4S probe.

- `l4s_interval`
  How often the L4S probe runs, in seconds.

### Example configuration

```json
{
    "client_name": "branch-office-01",
    "server_url": "https://monitor.example.com:5000",
    "test_interval": 60,
    "verify_ssl": true,
    "enable_l4s_testing": true,
    "l4s_target": "1.1.1.1",
    "l4s_interval": 600
}
```

## Running the Client

From this `client` directory:

```bash
python main.py
```

Run with an explicit config file:

```bash
python main.py --config client_config.json
```

Show the client version:

```bash
python main.py --version
```

## First Run Behavior

On first launch, the client checks whether `client_config.json` exists and contains usable values.

If it does not, the client will guide you through an interactive setup and save the configuration for future runs.

You may be prompted for:

- Client name
- Server URL
- SSL verification preference
- Test interval
- API key (optional)

## Available Commands

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the client:

```bash
python main.py
```

Run with explicit config:

```bash
python main.py --config client_config.json
```

Show version:

```bash
python main.py --version
```

## Building a Standalone Executable

You can package the client into a distributable binary with PyInstaller.

From this `client` directory:

```bash
pyinstaller VaneMonitorClient.spec
```

If you are using the monorepo build scripts from the repository root instead, use:

Windows PowerShell:

```powershell
.\scripts\build_client.ps1
```

Linux / macOS:

```bash
bash scripts/build_client.sh
```

## Troubleshooting

### Missing dependency errors

Make sure you installed the dependencies:

```bash
pip install -r requirements.txt
```

### SSL connection problems

If your server uses a self-signed certificate, set:

```json
"verify_ssl": false
```

Only do this where that is acceptable for your environment.

### Client keeps prompting for setup

Check that `client_config.json` contains real values for:

- `client_name`
- `server_url`

Leaving these blank or using placeholder defaults will trigger interactive setup again.

### Python command not found

Try one of these instead:

```bash
python3 main.py
```

or on Windows:

```powershell
py main.py
```

## Quick Start

```bash
git clone https://github.com/your-org/your-client-repo.git
cd your-client-repo/client
python -m venv .venv
pip install -r requirements.txt
python main.py
```
