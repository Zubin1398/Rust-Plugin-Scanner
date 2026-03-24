import argparse
from pathlib import Path

from core.exporters import export_html, export_json, export_txt
from core.scanner import scan_target


def main() -> int:
    # CHANGE: add a CLI entrypoint so scanner logic is usable without any GUI framework
    parser = argparse.ArgumentParser(description="Rust Plugin Security Scanner")
    parser.add_argument("path", help="Path to a .cs file or directory with plugins")
    parser.add_argument("--format", choices=["txt", "json", "html"], default="txt")
    parser.add_argument("--output", help="Output file path for report export")
    args = parser.parse_args()

    findings = scan_target(args.path)
    if args.output:
        output_path = str(Path(args.output))
        if args.format == "txt":
            export_txt(findings, output_path)
        elif args.format == "json":
            export_json(findings, output_path)
        else:
            export_html(findings, output_path)
        print(f"Saved {len(findings)} findings to {output_path}")
        return 0

    for finding in findings:
        print(f"[{finding.rule.severity}] {Path(finding.filepath).name}:{finding.line_no} {finding.rule.id} {finding.rule.title}")
    print(f"Total findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
