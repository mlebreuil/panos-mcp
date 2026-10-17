"""`panos-mcp-samples`: maintain the sample library (contracts/samples-cli.md).

Exit codes: 0 success, 1 validation/leak failure, 2 usage error,
3 live safety check failed (config changed or live mode not enabled).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from defusedxml import ElementTree as SafeET

from panos_mcp.samples.layout import default_samples_dir
from panos_mcp.samples.library import (
    SampleError,
    add_sample,
    build_index,
    sanitize_xml,
    validate_library,
)
from panos_mcp.samples.metadata import SampleRequest
from panos_mcp.samples.sanitize.forge import MappingDirError, MappingStore
from panos_mcp.samples.sanitize.leakcheck import lint

EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_LIVE = 0, 1, 2, 3


def _cmd_add(args: argparse.Namespace) -> int:
    request = SampleRequest(
        type=args.type,
        cmd=args.cmd,
        action=args.action,
        xpath=args.xpath,
        log_type=args.log_type,
        log_phase=args.log_phase,
        target=args.target,
    )
    store = MappingStore.open(args.mapping_dir)
    sample_id = add_sample(
        args.samples_dir,
        panos_version=args.version,
        request=request,
        variant=args.variant,
        xml=Path(args.file).read_text("utf-8"),
        source=args.source,
        description=args.description,
        slug=args.slug,
        url=args.url,
        notes=args.notes,
        tags=args.tag,
        store=store,
        force=args.force,
    )
    store.save()
    print(f"added {sample_id}")
    return EXIT_OK


def _cmd_sanitize(args: argparse.Namespace) -> int:
    store = MappingStore.open(args.mapping_dir)
    files: list[Path] = []
    for item in args.paths:
        path = Path(item)
        files.extend(sorted(path.rglob("*.xml")) if path.is_dir() else [path])
    status = EXIT_OK
    for path in files:
        text = path.read_text("utf-8")
        if args.check_only:
            findings = lint(text)
            for finding in findings:
                print(f"{path}: {finding}")
            if findings:
                status = EXIT_FAIL
            continue
        outcome = sanitize_xml(text, store, args.mode, args.samples_dir)
        path.write_text(outcome.xml + "\n", "utf-8")
        print(f"sanitized {path} ({len(outcome.originals)} values replaced)")
    store.save()
    return status


def _cmd_validate(args: argparse.Namespace) -> int:
    problems = validate_library(Path(args.path))
    for problem in problems:
        print(problem)
    print(f"{len(problems)} problem(s)")
    return EXIT_FAIL if problems else EXIT_OK


def _cmd_index(args: argparse.Namespace) -> int:
    out = args.samples_dir / "INDEX.md"
    out.write_text(build_index(args.samples_dir), "utf-8")
    print(f"wrote {out}")
    return EXIT_OK


def _cmd_generate(args: argparse.Namespace) -> int:
    from panos_mcp.samples.generate import generate_large_estate

    ids = generate_large_estate(
        args.samples_dir, devices=args.devices, rules=args.rules, seed=args.seed
    )
    print(f"generated {len(ids)} samples and scenario large-estate (git-ignored)")
    return EXIT_OK


def _cmd_capture(args: argparse.Namespace) -> int:
    from panos_mcp.samples.capture import run_capture_cli

    return run_capture_cli(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="panos-mcp-samples", description=__doc__)
    parser.add_argument(
        "--samples-dir", type=Path, default=None, help="sample library root (default: samples/)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("add", help="sanitize and register a response body as a sample")
    add.add_argument("--version", required=True, help="Panorama version, e.g. 11.1, or 'any'")
    add.add_argument("--type", required=True, choices=["op", "config", "log"])
    add.add_argument("--cmd")
    add.add_argument("--action", choices=["get", "show"])
    add.add_argument("--xpath")
    add.add_argument("--log-type", choices=["traffic", "threat", "url", "system", "config"])
    add.add_argument("--log-phase", choices=["start", "result"])
    add.add_argument("--target")
    add.add_argument("--slug")
    add.add_argument("--variant", required=True)
    add.add_argument(
        "--source", required=True, choices=["documentation", "synthetic", "lab-capture"]
    )
    add.add_argument("--url")
    add.add_argument("--description", required=True)
    add.add_argument("--notes")
    add.add_argument("--tag", action="append")
    add.add_argument("--force", action="store_true")
    add.add_argument("--mapping-dir", type=Path)
    add.add_argument("file")
    add.set_defaults(func=_cmd_add)

    san = sub.add_parser("sanitize", help="replace sensitive values with forged ones")
    san.add_argument("--mapping-dir", type=Path)
    san.add_argument("--check-only", action="store_true")
    san.add_argument("--mode", choices=["full", "synthetic"], default="full")
    san.add_argument("paths", nargs="+")
    san.set_defaults(func=_cmd_sanitize)

    val = sub.add_parser("validate", help="offline checks of the whole library")
    val.add_argument("path", nargs="?", default=None)
    val.set_defaults(func=_cmd_validate)

    idx = sub.add_parser("index", help="regenerate samples/INDEX.md")
    idx.set_defaults(func=_cmd_index)

    gen = sub.add_parser("generate", help="generate synthetic datasets")
    gen.add_argument("dataset", choices=["large-estate"])
    gen.add_argument("--devices", type=int, default=500)
    gen.add_argument("--rules", type=int, default=10000)
    gen.add_argument("--seed", type=int, default=42)
    gen.set_defaults(func=_cmd_generate)

    cap = sub.add_parser("capture", help="opt-in live capture (PANOS_MCP_LIVE=1)")
    cap.add_argument("--write-plan", type=Path, help="write the capture plan (offline) and exit")
    cap.add_argument("--plan", type=Path)
    cap.add_argument("--version")
    cap.add_argument("--variant")
    cap.add_argument("--mark-verified", nargs="*", help="sample ids to promote to verified")
    cap.add_argument("--mapping-dir", type=Path)
    cap.set_defaults(func=_cmd_capture)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.samples_dir is None:
        args.samples_dir = default_samples_dir()
    if getattr(args, "path", "unset") is None:
        args.path = args.samples_dir
    try:
        code: int = args.func(args)
    except (SampleError, MappingDirError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL
    except (SafeET.ParseError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return code


if __name__ == "__main__":
    raise SystemExit(main())
