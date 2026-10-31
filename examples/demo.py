"""
Demo: use llm-secrets-guard as a Python library in your own security pipeline.
"""

from pathlib import Path
from llm_secrets_guard import scan_path


def audit_project(project_path: str) -> None:
    result = scan_path(Path(project_path))

    print(f"Scanned {result.scanned_files} files")
    print(f"Found {len(result.findings)} potential secrets\n")

    if not result.findings:
        print("Clean! No leaked secrets detected.")
        return

    for finding in result.high_severity:
        print(f"[HIGH] {finding.provider} key at {finding.file}:{finding.line_number}")
        print(f"       {finding.line_preview}\n")

    for finding in result.medium_severity:
        print(f"[MEDIUM] {finding.provider} at {finding.file}:{finding.line_number}")

    # Fail the pipeline if HIGH findings exist
    if result.high_severity:
        raise SystemExit(
            f"\nBlocking: {len(result.high_severity)} HIGH severity secrets detected."
        )


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    audit_project(path)
