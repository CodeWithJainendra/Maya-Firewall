#!/usr/bin/env python3
import pathlib
import sys

import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CARGO_TOML = ROOT / "Cargo.toml"


def fail(message: str) -> None:
    print(f"metadata validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if not CARGO_TOML.exists():
        fail("Cargo.toml not found at workspace root")

    try:
        data = tomllib.loads(CARGO_TOML.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        fail(f"invalid TOML in Cargo.toml: {exc}")

    workspace = data.get("workspace")
    if not isinstance(workspace, dict):
        fail("missing [workspace] table")

    package = workspace.get("package")
    if not isinstance(package, dict):
        fail("missing [workspace.package] table")

    authors = package.get("authors")
    if not isinstance(authors, list) or not authors:
        fail("workspace.package.authors must be a non-empty array")

    invalid = [author for author in authors if not isinstance(author, str) or not author.strip()]
    if invalid:
        fail("workspace.package.authors contains empty/non-string entries")

    edition = package.get("edition")
    if not isinstance(edition, str) or not edition.strip():
        fail("workspace.package.edition must be a non-empty string")

    version = package.get("version")
    if not isinstance(version, str) or not version.strip():
        fail("workspace.package.version must be a non-empty string")

    print("workspace metadata validation passed")


if __name__ == "__main__":
    main()
