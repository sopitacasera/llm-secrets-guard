"""llm-secrets-guard — Detect leaked LLM API keys before they hit production."""

__version__ = "1.0.0"
__author__ = "Johanna Huaraca"

from .scanner import scan_path, scan_file, ScanResult, Finding
from .patterns import PATTERNS

__all__ = ["scan_path", "scan_file", "ScanResult", "Finding", "PATTERNS"]
