"""
Client module for Vane Monitor
"""
try:
    from .client import NetworkClient
    __all__ = ['NetworkClient']
except ImportError:
    # Allow package to be imported even when dependencies missing
    __all__ = []
