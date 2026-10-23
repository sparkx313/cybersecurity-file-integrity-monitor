"""Create and verify persistent SHA-256 file-integrity baselines."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


FORMAT_VERSION = 1
CHUNK_SIZE = 1024 * 1024


class IntegrityError(ValueError):
    """Raised when a directory or baseline cannot be processed safely."""


def _canonical(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _hash_file(path: Path) -> dict:
    try:
        before = os.stat(path, follow_symlinks=False)
        digest = hashlib.sha256()
        with path.open("rb") as file:
            while chunk := file.read(CHUNK_SIZE):
                digest.update(chunk)
        after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise IntegrityError(f"Could not read {path}: {exc}") from exc

    if not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(after.st_mode):
        raise IntegrityError(f"File type changed while scanning: {path}")
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
        after.st_size, after.st_mtime_ns, after.st_ino
    ):
        raise IntegrityError(f"File changed while it was being hashed: {path}")
    return {"sha256": digest.hexdigest(), "size": after.st_size}


def scan_directory(directory: Path, excluded_paths: set[Path] | None = None) -> tuple[dict, dict[str, str]]:
    root = directory.expanduser().resolve()
    if not root.is_dir():
        raise IntegrityError(f"Directory does not exist or is not a directory: {root}")
    excluded = {_canonical(path.expanduser().resolve()) for path in excluded_paths or set()}
    files: dict[str, dict] = {}
    skipped_entries: dict[str, str] = {}
    pending = [root]

    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError as exc:
            raise IntegrityError(f"Could not list directory {current}: {exc}") from exc

        for entry in entries:
            path = Path(entry.path)
            if _canonical(path) in excluded:
                continue
            relative_path = path.relative_to(root).as_posix()
            try:
                if entry.is_symlink():
                    skipped_entries[relative_path] = "symlink"
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    skipped_entries[relative_path] = "special"
                    continue
            except OSError as exc:
                raise IntegrityError(f"Could not inspect {path}: {exc}") from exc

            files[relative_path] = _hash_file(path)

    return dict(sorted(files.items())), dict(sorted(skipped_entries.items()))


def build_baseline(directory: Path, manifest_path: Path) -> dict:
    root = directory.expanduser().resolve()
    manifest = manifest_path.expanduser().resolve()
    if _canonical(manifest) == _canonical(root):
        raise IntegrityError("The manifest path must be a file, not the monitored directory.")
    if _is_within(manifest, root) and manifest.exists():
        try:
            load_baseline(manifest)
        except IntegrityError as exc:
            raise IntegrityError(
                "Refusing to overwrite an existing non-baseline file inside the monitored directory. "
                "Choose a manifest path outside it."
            ) from exc
    files, skipped = scan_directory(root, {manifest})
    return {
        "format_version": FORMAT_VERSION,
        "hash_algorithm": "sha256",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_for": str(root),
        "files": files,
        "skipped_entries": skipped,
    }


def load_baseline(path: Path) -> dict:
    try:
        data = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"Could not read baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("format_version") != FORMAT_VERSION:
        raise IntegrityError("Unsupported or malformed baseline format.")
    if data.get("hash_algorithm") != "sha256" or not isinstance(data.get("files"), dict):
        raise IntegrityError("Baseline must contain SHA-256 file entries.")
    skipped_entries = data.get("skipped_entries", {})
    if not isinstance(skipped_entries, dict):
        raise IntegrityError("Baseline skipped-entry data is malformed.")

    for relative_name, entry in data["files"].items():
        relative = PurePosixPath(relative_name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise IntegrityError(f"Unsafe relative path in baseline: {relative_name!r}")
        if not isinstance(entry, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            raise IntegrityError(f"Invalid SHA-256 value for {relative_name!r}.")
        if type(entry.get("size")) is not int or entry["size"] < 0:
            raise IntegrityError(f"Invalid file size for {relative_name!r}.")
    for relative_name, kind in skipped_entries.items():
        relative = PurePosixPath(relative_name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise IntegrityError(f"Unsafe skipped path in baseline: {relative_name!r}")
        if kind not in {"symlink", "special"}:
            raise IntegrityError(f"Invalid skipped-entry type for {relative_name!r}.")
    return data


def verify_directory(directory: Path, baseline: dict, excluded_paths: set[Path] | None = None) -> dict:
    root = directory.expanduser().resolve()
    current_files, skipped_entries = scan_directory(root, excluded_paths)
    baseline_files = baseline["files"]
    old_paths = set(baseline_files)
    new_paths = set(current_files)
    added = sorted(new_paths - old_paths)
    removed = sorted(old_paths - new_paths)
    modified = sorted(
        path for path in old_paths & new_paths
        if baseline_files[path]["sha256"] != current_files[path]["sha256"]
        or baseline_files[path]["size"] != current_files[path]["size"]
    )
    unchanged = len(old_paths & new_paths) - len(modified)
    old_skipped = baseline.get("skipped_entries", {})
    changed_skipped = [
        {"path": path, "baseline": old_skipped.get(path), "current": skipped_entries.get(path)}
        for path in sorted(set(old_skipped) | set(skipped_entries))
        if old_skipped.get(path) != skipped_entries.get(path)
    ]
    if added or removed or modified or changed_skipped:
        status = "changed"
    elif skipped_entries:
        status = "incomplete"
    else:
        status = "clean"
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "directory": str(root),
        "baseline_created_at": baseline.get("created_at"),
        "hash_algorithm": "sha256",
        "counts": {
            "checked": len(current_files),
            "unchanged": unchanged,
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
            "skipped_symlinks": sum(kind == "symlink" for kind in skipped_entries.values()),
            "skipped_special_files": sum(kind == "special" for kind in skipped_entries.values()),
        },
        "added": added,
        "removed": removed,
        "modified": modified,
        "skipped_entry_changes": changed_skipped,
        "unverified_entries": skipped_entries,
        "status": status,
        "limitations": [
            "The baseline file is the trust anchor; keep it outside the monitored directory or protect it separately.",
            "This command compares snapshots; it does not watch filesystem events in real time.",
            "Symlinks and special files are recorded but not hashed.",
        ],
    }


def write_json(path: Path, data: dict) -> None:
    requested_path = path.expanduser()
    if requested_path.is_symlink():
        raise IntegrityError(f"Refusing to replace a symbolic-link destination: {requested_path}")
    destination = requested_path.resolve()
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", prefix=f".{destination.name}.",
            suffix=".tmp", dir=destination.parent, delete=False,
        ) as output:
            temporary = Path(output.name)
            json.dump(data, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise IntegrityError(f"Could not write {destination}: {exc}") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create and verify SHA-256 file-integrity snapshots.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("baseline", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--directory", required=True, type=Path, help="directory to monitor")
        command.add_argument(
            "--manifest", type=Path, default=Path("file-integrity-baseline.json"),
            help="baseline JSON path (default: file-integrity-baseline.json)",
        )
        if name == "verify":
            command.add_argument("--report", type=Path, help="optional verification report JSON path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "baseline":
            baseline = build_baseline(args.directory, args.manifest)
            write_json(args.manifest, baseline)
            print(f"Baseline saved to {args.manifest.expanduser().resolve()}")
            skipped = baseline["skipped_entries"]
            symlinks = sum(kind == "symlink" for kind in skipped.values())
            special_files = sum(kind == "special" for kind in skipped.values())
            print(f"Hashed {len(baseline['files'])} files; recorded {symlinks} symlinks and {special_files} special files.")
            return 0

        baseline_path = args.manifest.expanduser().resolve()
        baseline = load_baseline(baseline_path)
        excluded = {baseline_path}
        if args.report:
            report_path = args.report.expanduser().resolve()
            if _canonical(report_path) == _canonical(baseline_path):
                raise IntegrityError("The verification report must not overwrite the baseline.")
            if _is_within(report_path, args.directory.expanduser().resolve()):
                raise IntegrityError("The verification report must be outside the monitored directory.")
        report = verify_directory(args.directory, baseline, excluded)
        if args.report:
            write_json(args.report, report)
        counts = report["counts"]
        print(
            f"Status: {report['status']} | checked={counts['checked']} "
            f"added={counts['added']} removed={counts['removed']} "
            f"modified={counts['modified']} skipped_symlinks={counts['skipped_symlinks']} "
            f"skipped_special_files={counts['skipped_special_files']}"
        )
        for label in ("added", "removed", "modified"):
            for relative_path in report[label]:
                print(f"{label.upper()}: {relative_path}")
        for item in report["skipped_entry_changes"]:
            print(f"UNVERIFIED ENTRY CHANGE: {item['path']} ({item['baseline']} -> {item['current']})")
        if args.report:
            print(f"Report saved to {args.report.expanduser().resolve()}")
        if report["status"] == "changed":
            return 1
        if report["status"] == "incomplete":
            print("The directory contains symlinks or special files that were not hashed.", file=sys.stderr)
            return 2
        return 0
    except IntegrityError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
