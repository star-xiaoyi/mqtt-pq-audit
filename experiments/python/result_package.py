#!/usr/bin/env python3
"""Tamper-evident, single-run result-package primitives.

The completion manifest is deliberately written last.  A directory without it
is an interrupted/staging run, never a completed result package.  Completed
packages are immutable: every regular file other than the manifest itself is
declared by relative path, byte length, and SHA-256 digest, and extra files are
rejected just like missing or modified files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


CONFIG_SCHEMA = "aapa-protocol-config-v2"
METADATA_SCHEMA = "aapa-result-package-metadata-v2"
MANIFEST_SCHEMA = "aapa-result-package-completion-v2"
CONFIG_NAME = "protocol_config.json"
METADATA_NAME = "package_metadata.json"
MANIFEST_NAME = "completion_manifest.json"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class PackageError(ValueError):
    """Raised when a result package violates an integrity invariant."""


@dataclass(frozen=True)
class IntegrityIssue:
    code: str
    detail: str


def canonical_json_bytes(value: Any) -> bytes:
    """Return the one canonical encoding used for all metadata hashes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def object_hash(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def validate_timestamp_utc(value: str) -> str:
    if not _RFC3339_UTC_RE.fullmatch(value):
        raise PackageError(f"timestamp_utc must be RFC 3339 UTC seconds: {value!r}")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PackageError(f"invalid timestamp_utc: {value!r}") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise PackageError(f"non-canonical timestamp_utc: {value!r}")
    return value


def config_payload(config: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(config)
    payload.pop("config_hash", None)
    return payload


def calculate_config_hash(config: Mapping[str, Any]) -> str:
    return object_hash(config_payload(config))


def seal_config(config: Mapping[str, Any]) -> dict[str, Any]:
    sealed = config_payload(config)
    sealed["config_hash"] = calculate_config_hash(sealed)
    return sealed


def atomic_write_json(path: Path, value: Any) -> None:
    """Atomically replace *path* with canonical, human-readable JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temp.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageError(f"cannot parse {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise PackageError(f"{path.name} must contain a JSON object")
    return value


def ensure_new_result_target(path: Path) -> None:
    """Reject reuse, including an existing empty directory.

    Requiring a new pathname is stricter than merely rejecting non-empty
    directories and closes races where an earlier failed run left hidden state.
    """
    if path.exists() or path.is_symlink():
        kind = "directory" if path.is_dir() else "path"
        raise PackageError(f"result {kind} already exists; choose a fresh --out-dir: {path}")


def _safe_manifest_path(value: str) -> bool:
    pure = PurePosixPath(value)
    return (
        bool(value)
        and not pure.is_absolute()
        and ".." not in pure.parts
        and "." not in pure.parts
        and "\\" not in value
        and value != MANIFEST_NAME
    )


def iter_package_files(package_dir: Path) -> Iterable[tuple[str, Path]]:
    for path in sorted(package_dir.rglob("*")):
        if path.is_symlink():
            raise PackageError(f"symlinks are forbidden in result packages: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(package_dir).as_posix()
        if relative == MANIFEST_NAME:
            continue
        if not _safe_manifest_path(relative):
            raise PackageError(f"unsafe package path: {relative!r}")
        yield relative, path


def validate_config(config: Mapping[str, Any]) -> list[IntegrityIssue]:
    issues: list[IntegrityIssue] = []
    if config.get("schema") != CONFIG_SCHEMA:
        issues.append(IntegrityIssue("CONFIG_SCHEMA", f"schema={config.get('schema')!r}"))
    if config.get("mode") not in {"quick", "full"}:
        issues.append(IntegrityIssue("CONFIG_MODE", f"mode={config.get('mode')!r}"))
    if not isinstance(config.get("run_id"), str) or not config.get("run_id"):
        issues.append(IntegrityIssue("CONFIG_RUN_ID", "run_id must be a non-empty string"))
    try:
        validate_timestamp_utc(str(config.get("timestamp_utc", "")))
    except PackageError as exc:
        issues.append(IntegrityIssue("CONFIG_TIMESTAMP", str(exc)))
    seed = config.get("seed")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**64:
        issues.append(IntegrityIssue("CONFIG_SEED", f"seed must be uint64, got {seed!r}"))
    expected_hash = calculate_config_hash(config)
    if config.get("config_hash") != expected_hash:
        issues.append(
            IntegrityIssue(
                "CONFIG_HASH",
                f"declared={config.get('config_hash')!r} calculated={expected_hash}",
            )
        )
    return issues


def _cross_metadata_issues(
    config: Mapping[str, Any], metadata: Mapping[str, Any]
) -> list[IntegrityIssue]:
    issues: list[IntegrityIssue] = []
    if metadata.get("schema") != METADATA_SCHEMA:
        issues.append(IntegrityIssue("METADATA_SCHEMA", f"schema={metadata.get('schema')!r}"))
    for field in ("run_id", "timestamp_utc", "mode", "seed", "config_hash"):
        if metadata.get(field) != config.get(field):
            issues.append(
                IntegrityIssue(
                    "METADATA_MISMATCH",
                    f"{field}: metadata={metadata.get(field)!r} config={config.get(field)!r}",
                )
            )
    dependencies = metadata.get("dependencies")
    if not isinstance(dependencies, dict):
        issues.append(IntegrityIssue("DEPENDENCIES", "dependencies must be an object"))
    elif metadata.get("dependency_hash") != object_hash(dependencies):
        issues.append(
            IntegrityIssue(
                "DEPENDENCY_HASH",
                f"declared={metadata.get('dependency_hash')!r} calculated={object_hash(dependencies)}",
            )
        )
    git_commit = metadata.get("git_commit")
    if not isinstance(git_commit, str) or not _GIT_OBJECT_RE.fullmatch(git_commit):
        issues.append(IntegrityIssue("METADATA_GIT_COMMIT", f"git_commit={git_commit!r}"))
    for field in ("source_tree_hash", "dependency_hash"):
        value = metadata.get(field)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            issues.append(IntegrityIssue("METADATA_DIGEST", f"{field}={value!r}"))
    if not isinstance(metadata.get("git_dirty"), bool):
        issues.append(IntegrityIssue("METADATA_DIRTY", "git_dirty must be boolean"))
    return issues


def validate_metadata(
    config: Mapping[str, Any], metadata: Mapping[str, Any]
) -> list[IntegrityIssue]:
    """Public package-metadata validation entry point."""
    return _cross_metadata_issues(config, metadata)


def write_package_metadata(
    package_dir: Path,
    *,
    config: Mapping[str, Any],
    preflight_snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    git = preflight_snapshot.get("git", {})
    dependencies = dict(preflight_snapshot.get("dependencies", {}))
    metadata = {
        "schema": METADATA_SCHEMA,
        "run_id": config["run_id"],
        "timestamp_utc": config["timestamp_utc"],
        "mode": config["mode"],
        "seed": config["seed"],
        "config_hash": config["config_hash"],
        "git_commit": git.get("commit"),
        "git_dirty": git.get("dirty"),
        "git_branch": git.get("branch"),
        "source_tree_hash": git.get("source_tree_hash"),
        "dependencies": dependencies,
        "dependency_hash": object_hash(dependencies),
        "environment": preflight_snapshot.get("environment", {}),
    }
    issues = _cross_metadata_issues(config, metadata)
    if issues:
        raise PackageError("invalid package metadata: " + "; ".join(x.detail for x in issues))
    atomic_write_json(package_dir / METADATA_NAME, metadata)
    return metadata


def create_completion_manifest(package_dir: Path) -> dict[str, Any]:
    """Hash the complete package and atomically mark it completed.

    The quality report must already exist and be independently computed.  A
    completion marker is never written for WARN/FAIL packages.
    """
    manifest_path = package_dir / MANIFEST_NAME
    if manifest_path.exists() or manifest_path.is_symlink():
        raise PackageError(f"completion manifest already exists: {manifest_path}")
    config = load_json_object(package_dir / CONFIG_NAME)
    metadata = load_json_object(package_dir / METADATA_NAME)
    issues = [*validate_config(config), *_cross_metadata_issues(config, metadata)]
    quality = load_json_object(package_dir / "quality_report.json")
    if quality.get("overall_status") != "PASS":
        issues.append(
            IntegrityIssue(
                "QUALITY_NOT_PASS",
                f"quality_report overall_status={quality.get('overall_status')!r}",
            )
        )
    for field in ("run_id", "timestamp_utc", "mode", "config_hash"):
        if quality.get(field) != config.get(field):
            issues.append(
                IntegrityIssue(
                    "QUALITY_CONTEXT",
                    f"{field}: quality={quality.get(field)!r} config={config.get(field)!r}",
                )
            )
    if issues:
        raise PackageError(
            "cannot complete package: "
            + "; ".join(f"{issue.code}:{issue.detail}" for issue in issues)
        )

    files = []
    for relative, path in iter_package_files(package_dir):
        stat = path.stat()
        files.append({"path": relative, "size_bytes": stat.st_size, "sha256": sha256_file(path)})
    if not files:
        raise PackageError("cannot complete an empty package")
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "run_id": config["run_id"],
        "timestamp_utc": config["timestamp_utc"],
        "mode": config["mode"],
        "seed": config["seed"],
        "config_hash": config["config_hash"],
        "git_commit": metadata["git_commit"],
        "source_tree_hash": metadata["source_tree_hash"],
        "dependency_hash": metadata["dependency_hash"],
        "quality_status": "PASS",
        "completed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "file_count": len(files),
        "files": files,
    }
    atomic_write_json(manifest_path, manifest)
    return manifest


def validate_completion_manifest(package_dir: Path) -> list[IntegrityIssue]:
    """Validate metadata, strict file membership, sizes, and hashes read-only."""
    issues: list[IntegrityIssue] = []
    try:
        config = load_json_object(package_dir / CONFIG_NAME)
        metadata = load_json_object(package_dir / METADATA_NAME)
        manifest = load_json_object(package_dir / MANIFEST_NAME)
    except PackageError as exc:
        return [IntegrityIssue("PACKAGE_JSON", str(exc))]

    issues.extend(validate_config(config))
    issues.extend(_cross_metadata_issues(config, metadata))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        issues.append(IntegrityIssue("MANIFEST_SCHEMA", f"schema={manifest.get('schema')!r}"))
    for field in (
        "run_id",
        "timestamp_utc",
        "mode",
        "seed",
        "config_hash",
        "git_commit",
        "source_tree_hash",
        "dependency_hash",
    ):
        reference = config.get(field) if field in config else metadata.get(field)
        if manifest.get(field) != reference:
            issues.append(
                IntegrityIssue(
                    "MANIFEST_MISMATCH",
                    f"{field}: manifest={manifest.get(field)!r} reference={reference!r}",
                )
            )
    if manifest.get("quality_status") != "PASS":
        issues.append(
            IntegrityIssue("MANIFEST_QUALITY", f"quality_status={manifest.get('quality_status')!r}")
        )

    entries = manifest.get("files")
    declared: dict[str, dict[str, Any]] = {}
    if not isinstance(entries, list):
        issues.append(IntegrityIssue("MANIFEST_FILES", "files must be an array"))
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            issues.append(IntegrityIssue("MANIFEST_ENTRY", f"non-object entry={entry!r}"))
            continue
        relative = entry.get("path")
        if not isinstance(relative, str) or not _safe_manifest_path(relative):
            issues.append(IntegrityIssue("MANIFEST_PATH", f"unsafe path={relative!r}"))
            continue
        if relative in declared:
            issues.append(IntegrityIssue("MANIFEST_DUPLICATE", f"duplicate path={relative!r}"))
            continue
        declared[relative] = entry
    if manifest.get("file_count") != len(entries):
        issues.append(
            IntegrityIssue(
                "MANIFEST_COUNT",
                f"file_count={manifest.get('file_count')!r} entries={len(entries)}",
            )
        )
    if [entry.get("path") for entry in entries if isinstance(entry, dict)] != sorted(declared):
        issues.append(IntegrityIssue("MANIFEST_ORDER", "file entries are not uniquely path-sorted"))

    try:
        actual = dict(iter_package_files(package_dir))
    except PackageError as exc:
        issues.append(IntegrityIssue("PACKAGE_PATH", str(exc)))
        actual = {}
    for relative in sorted(set(declared) - set(actual)):
        issues.append(IntegrityIssue("FILE_MISSING", relative))
    for relative in sorted(set(actual) - set(declared)):
        issues.append(IntegrityIssue("FILE_UNDECLARED", relative))
    for relative in sorted(set(declared) & set(actual)):
        entry = declared[relative]
        path = actual[relative]
        size = path.stat().st_size
        digest = sha256_file(path)
        if entry.get("size_bytes") != size:
            issues.append(
                IntegrityIssue(
                    "FILE_SIZE",
                    f"{relative}: declared={entry.get('size_bytes')!r} actual={size}",
                )
            )
        if entry.get("sha256") != digest:
            issues.append(
                IntegrityIssue(
                    "FILE_HASH",
                    f"{relative}: declared={entry.get('sha256')!r} actual={digest}",
                )
            )
    return issues
