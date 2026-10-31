"""
CLI entry point — llm-secrets-guard scan [path] [options]
"""

import sys
import json
import argparse
from pathlib import Path

from .scanner import scan_path

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _color(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{RESET}"
    return text


def _severity_color(severity: str) -> str:
    return RED if severity == "HIGH" else YELLOW


def print_banner():
    banner = r"""
  _ _           ___                     _         ____
 | | |_ __ ___ / __| ___  __ _ _ _ ___ | |_ ___  / ___|_   _  __ _ _ __ __| |
 | | | '_ ` _ \\___ \/ _ \/ _` | '_/ -_)|  _(_-< | |  _| | | |/ _` | '__/ _` |
 |_|_| | | | | |___/\___/\__,_|_| \___| \__/__/  \____\ |_,_|\__,_|_| \__,_|
"""
    print(_color(banner, CYAN))
    print(_color("  Detect leaked LLM API keys before they reach production\n", BOLD))


def run():
    parser = argparse.ArgumentParser(
        prog="llm-secrets-guard",
        description="Scan code for leaked LLM API keys (OpenAI, Azure, Anthropic, etc.)",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--output", "-o",
        help="Save JSON report to file",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 1 if any HIGH severity finding is detected (use in CI)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress banner",
    )

    args = parser.parse_args()
    target = Path(args.path).resolve()

    if not target.exists():
        print(f"Error: path '{target}' does not exist.", file=sys.stderr)
        sys.exit(2)

    if not args.json and not args.no_banner:
        print_banner()

    result = scan_path(target)

    # JSON output mode
    if args.json or args.output:
        json_output = result.to_json()
        if args.output:
            Path(args.output).write_text(json_output, encoding="utf-8")
            print(f"Report saved to {args.output}")
        else:
            print(json_output)
        if args.fail_on_findings and result.high_severity:
            sys.exit(1)
        return

    # Human-readable output
    print(f"Scanning: {_color(str(target), CYAN)}")
    print(f"Files scanned: {result.scanned_files} | Skipped: {result.skipped_files}\n")

    if not result.findings:
        print(_color("No secrets found. Your code is clean!", GREEN))
        return

    # Group by file
    findings_by_file: dict = {}
    for f in result.findings:
        findings_by_file.setdefault(f.file, []).append(f)

    for file_path, findings in findings_by_file.items():
        print(_color(f"FILE: {file_path}", BOLD))
        for finding in findings:
            sev_color = _severity_color(finding.severity)
            print(
                f"  Line {finding.line_number:4d}  "
                f"[{_color(finding.severity, sev_color)}]  "
                f"{_color(finding.provider, CYAN)}  —  {finding.description}"
            )
            print(f"           {finding.line_preview}")
        print()

    total = len(result.findings)
    high = len(result.high_severity)
    medium = len(result.medium_severity)

    print("─" * 60)
    print(
        f"SUMMARY: {_color(str(total) + ' findings', BOLD)}  |  "
        f"{_color(str(high) + ' HIGH', RED)}  |  "
        f"{_color(str(medium) + ' MEDIUM', YELLOW)}"
    )

    if result.high_severity:
        print(_color("\nAction required: revoke and rotate the exposed keys immediately.", RED))
        print("Use .env files + Azure Key Vault / GitHub Secrets for all LLM credentials.\n")

    if args.fail_on_findings and result.high_severity:
        sys.exit(1)


if __name__ == "__main__":
    run()
