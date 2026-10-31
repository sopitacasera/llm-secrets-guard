"""
Core scanning engine — finds LLM API key leaks in files and directories.
"""

import os
import re
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional

from .patterns import PATTERNS, SCAN_EXTENSIONS, IGNORE_PATHS, SecretPattern


@dataclass
class Finding:
    file: str
    line_number: int
    line_preview: str  # redacted
    pattern_name: str
    provider: str
    severity: str
    description: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    scanned_files: int = 0
    skipped_files: int = 0
    findings: List[Finding] = field(default_factory=list)

    @property
    def high_severity(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def medium_severity(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "MEDIUM"]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "summary": {
                    "scanned_files": self.scanned_files,
                    "total_findings": len(self.findings),
                    "high_severity": len(self.high_severity),
                    "medium_severity": len(self.medium_severity),
                },
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=indent,
        )


def _redact_line(line: str, match: re.Match) -> str:
    """Replace the matched secret with asterisks, keeping first 4 chars."""
    start, end = match.span()
    secret = line[start:end]
    if len(secret) > 8:
        redacted = secret[:4] + "*" * (len(secret) - 4)
    else:
        redacted = "*" * len(secret)
    return line[:start] + redacted + line[end:]


def _should_skip(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORE_PATHS:
            return True
    return False


def scan_file(file_path: Path) -> List[Finding]:
    findings: List[Finding] = []

    if file_path.suffix not in SCAN_EXTENSIONS and file_path.name != ".env":
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        for pattern in PATTERNS:
            try:
                for match in re.finditer(pattern.regex, line):
                    redacted = _redact_line(line.strip(), match)
                    findings.append(
                        Finding(
                            file=str(file_path),
                            line_number=line_num,
                            line_preview=redacted[:120],
                            pattern_name=pattern.name,
                            provider=pattern.provider,
                            severity=pattern.severity,
                            description=pattern.description,
                        )
                    )
            except re.error:
                continue

    return findings


def scan_path(target: Path, extensions: Optional[set] = None) -> ScanResult:
    result = ScanResult()
    ext_filter = extensions or SCAN_EXTENSIONS

    if target.is_file():
        if not _should_skip(target):
            result.scanned_files += 1
            result.findings.extend(scan_file(target))
        return result

    for root, dirs, files in os.walk(target):
        root_path = Path(root)

        # Prune ignored directories in-place so os.walk skips them
        dirs[:] = [d for d in dirs if d not in IGNORE_PATHS]

        for fname in files:
            file_path = root_path / fname
            if _should_skip(file_path):
                result.skipped_files += 1
                continue
            if file_path.suffix in ext_filter or fname == ".env":
                result.scanned_files += 1
                result.findings.extend(scan_file(file_path))
            else:
                result.skipped_files += 1

    return result
