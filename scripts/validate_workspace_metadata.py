#!/usr/bin/env python3
import pathlib
import re
import sys
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        print(
            "metadata validation failed: requires Python 3.11+ (tomllib) or installed 'tomli'",
            file=sys.stderr,
        )
        raise SystemExit(1)

ROOT = pathlib.Path(__file__).resolve().parents[1]
CARGO_TOML = ROOT / "Cargo.toml"
ALLOWED_EDITIONS = {"2018", "2021", "2024"}
ALLOWED_RESOLVERS = {"1", "2", "3"}
GLOB_CHARS = {"*", "?", "["}
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SPDX_TOKEN_RE = re.compile(r"\(|\)|AND|OR|WITH|[A-Za-z0-9.+:-]+")
AUTHOR_WITH_EMAIL_RE = re.compile(r"^\s*[^<>]+\s*<[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+>\s*$")


def fail(message: str) -> None:
    print(f"metadata validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def is_workspace_inherited(value: object) -> bool:
    return isinstance(value, dict) and value.get("workspace") is True


def validate_publish_field(value: object, where: str) -> None:
    if value is None:
        return

    if is_workspace_inherited(value):
        return

    if isinstance(value, bool):
        return

    if isinstance(value, list) and value and all(isinstance(item, str) and item.strip() for item in value):
        return

    fail(f"{where}.publish must be bool or non-empty string array")


def validate_author(author: str) -> bool:
    candidate = author.strip()
    if "<" in candidate or ">" in candidate:
        return bool(AUTHOR_WITH_EMAIL_RE.match(candidate))

    if "@" in candidate:
        return False

    return any(ch.isalpha() for ch in candidate)


def looks_like_glob(pattern: str) -> bool:
    return any(ch in pattern for ch in GLOB_CHARS)


def parse_spdx_expression(value: str) -> bool:
    text = value.strip()
    if not text:
        return False

    tokens = SPDX_TOKEN_RE.findall(text)
    if "".join(tokens) != "".join(text.split()):
        return False

    position = 0

    def peek() -> Optional[str]:
        return tokens[position] if position < len(tokens) else None

    def consume(expected: Optional[str] = None) -> Optional[str]:
        nonlocal position
        token = peek()
        if token is None:
            return None
        if expected is not None and token != expected:
            return None
        position += 1
        return token

    def parse_factor() -> bool:
        token = peek()
        if token is None:
            return False
        if token == "(":
            consume("(")
            if not parse_expr():
                return False
            return consume(")") is not None
        if token in {"AND", "OR", "WITH", ")"}:
            return False
        consume()
        return True

    def parse_term() -> bool:
        if not parse_factor():
            return False
        if peek() == "WITH":
            consume("WITH")
            token = peek()
            if token is None or token in {"AND", "OR", "WITH", "(", ")"}:
                return False
            consume()
        return True

    def parse_expr() -> bool:
        if not parse_term():
            return False
        while peek() in {"AND", "OR"}:
            consume()
            if not parse_term():
                return False
        return True

    if not parse_expr():
        return False

    return position == len(tokens)


def resolve_workspace_members(members: list[str]) -> list[tuple[str, pathlib.Path]]:
    resolved: list[tuple[str, pathlib.Path]] = []
    seen: dict[str, str] = {}

    for member in members:
        pattern = member.strip()
        matches: list[pathlib.Path]

        if looks_like_glob(pattern):
            matches = [path for path in ROOT.glob(pattern) if path.is_dir()]
            if not matches:
                fail(f"workspace member glob did not match any directories: {pattern}")
        else:
            matches = [ROOT / pattern]

        for match in matches:
            cargo_toml = match / "Cargo.toml"
            if not match.exists() or not match.is_dir():
                fail(f"workspace member path not found: {match}")
            if not cargo_toml.exists():
                fail(
                    "workspace member missing Cargo.toml: "
                    + str(match.relative_to(ROOT).as_posix())
                )

            key = str(match.resolve())
            if key in seen:
                existing = seen[key]
                fail(
                    "workspace.members contains overlapping/duplicate member match: "
                    f"{match.relative_to(ROOT).as_posix()} (from '{pattern}', already matched by '{existing}')"
                )
            seen[key] = pattern
            resolved.append((str(match.relative_to(ROOT).as_posix()), match))

    return resolved


def main() -> None:
    if not CARGO_TOML.exists():
        fail("Cargo.toml not found at workspace root")

    try:
        content = CARGO_TOML.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"failed reading Cargo.toml: {exc}")
    except UnicodeDecodeError as exc:
        fail(f"Cargo.toml is not valid UTF-8: {exc}")

    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        fail(f"invalid TOML in Cargo.toml: {exc}")

    workspace = data.get("workspace")
    if not isinstance(workspace, dict):
        fail("missing [workspace] table")

    package = workspace.get("package")
    if not isinstance(package, dict):
        fail("missing [workspace.package] table")

    resolver = workspace.get("resolver")
    if resolver not in ALLOWED_RESOLVERS:
        fail(
            "workspace.resolver must be one of: " + ", ".join(sorted(ALLOWED_RESOLVERS))
        )

    members = workspace.get("members")
    if not isinstance(members, list) or not members:
        fail("workspace.members must be a non-empty array")
    if any(not isinstance(member, str) or not member.strip() for member in members):
        fail("workspace.members contains empty/non-string entries")

    resolved_members = resolve_workspace_members(members)

    for member, member_path in resolved_members:
        member_cargo = member_path / "Cargo.toml"

        try:
            member_data = tomllib.loads(member_cargo.read_text(encoding="utf-8"))
        except OSError as exc:
            fail(f"failed reading {member}/Cargo.toml: {exc}")
        except UnicodeDecodeError as exc:
            fail(f"{member}/Cargo.toml is not valid UTF-8: {exc}")
        except tomllib.TOMLDecodeError as exc:
            fail(f"invalid TOML in {member}/Cargo.toml: {exc}")

        member_package = member_data.get("package")
        if not isinstance(member_package, dict):
            fail(f"missing [package] table in {member}/Cargo.toml")

        if not isinstance(member_package.get("name"), str) or not member_package["name"].strip():
            fail(f"{member}/Cargo.toml package.name must be a non-empty string")

        validate_publish_field(member_package.get("publish"), f"{member}/Cargo.toml package")

    authors = package.get("authors")
    if not isinstance(authors, list) or not authors:
        fail("workspace.package.authors must be a non-empty array")

    invalid = [
        author
        for author in authors
        if not isinstance(author, str) or not author.strip() or not validate_author(author)
    ]
    if invalid:
        fail("workspace.package.authors contains malformed entries")

    normalized_authors = [" ".join(author.strip().split()).casefold() for author in authors]
    if len(set(normalized_authors)) != len(normalized_authors):
        fail("workspace.package.authors contains duplicate entries")

    edition = package.get("edition")
    if not isinstance(edition, str) or not edition.strip():
        fail("workspace.package.edition must be a non-empty string")
    if edition not in ALLOWED_EDITIONS:
        fail(
            "workspace.package.edition must be one of: "
            + ", ".join(sorted(ALLOWED_EDITIONS))
        )

    version = package.get("version")
    if not isinstance(version, str) or not version.strip():
        fail("workspace.package.version must be a non-empty string")
    normalized_version = version[1:] if version.startswith("v") else version
    if not SEMVER_RE.match(normalized_version):
        fail("workspace.package.version must be valid SemVer (e.g., 1.2.3)")

    license_value = package.get("license")
    if not isinstance(license_value, str) or not license_value.strip():
        fail("workspace.package.license must be a non-empty string")
    if not parse_spdx_expression(license_value):
        fail("workspace.package.license must look like a valid SPDX expression")

    description = package.get("description")
    if not isinstance(description, str) or not description.strip():
        fail("workspace.package.description must be a non-empty string")

    validate_publish_field(package.get("publish"), "workspace.package")

    print("workspace metadata validation passed")


if __name__ == "__main__":
    main()
