#!/usr/bin/env python3
"""Fail when docs/model/README.md cites code that is not defined where it says.

The README's code-location tables map model actions to Rust functions, types
and files. A table cell names its code in backticks. This check fails when

  * a cited source file (`split.rs`, `policy/endpoint.rs`, `tests/x.py`) matches
    no tracked file;
  * a `file.rs` `word` pair (`split.rs` `cancel`) names a function that the
    cited file does not define with `fn`;
  * a `Type::member` reference names a member that no `impl`, `trait`, `enum` or
    `struct` body of that type has, in the code the row can mean;
  * a bare `snake_case` or `CamelCase` name is neither defined (`fn`, `struct`,
    `enum`, `trait`, `type`, `const`, `static`, `mod`) nor used as a word of the
    code (comments and string literals do not count) in the code the row can mean;
  * a table that cites `.rs` files has no recognized code column, yields no
    checkable name, or has a row with fewer cells than its header (rows are
    split at every unescaped `|`, whatever the spaces around it).

"The code the row can mean" is the crates of the files it cites, the directories
it cites, and the crates it names (`marsh-backend`); a row that cites none is
checked against every Rust source. Only the code columns are read: the last
column of a table whose header says code, Rust or mapping. Words that are not
Rust are not checked: model names (any word a docs/model/*.tla file uses),
config names such as `reapOff`, break modes such as `lease-none`, shell commands
and JSON files. A bare lowercase word with no underscore is checked only right
after a file (`split.rs` `cancel`): elsewhere it may be a state or a value.

Dotted and call forms (`SplitCreateSpec.detach`, `store.job_limits()`) are not
Rust references to this check: they are not checked at all.

What this does not prove: that a function still does what its row says, or that
a bare name is a definition rather than a field or variant. It catches a rename
or deletion, a method that moved to another type, and a table that stopped being
read.

  check-model-locations.py [--readme PATH] [--root DIR]
"""
from __future__ import annotations

import argparse
import functools
import pathlib
import re
import subprocess
import sys

SEGMENT = r"[A-Za-z_][A-Za-z0-9_]*"
BRACES = re.compile(r"\{([^{}]*)\}")
CODE = re.compile(r"`([^`\n]+)`")
CRATE = re.compile(r"\bmarsh-[a-z0-9-]+\b")
FILE_EXTENSIONS = (".rs", ".py", ".sh", ".mjs", ".toml", ".yml", ".yaml")
# Rust keywords and lowercase words that the table puts in backticks as values.
NOT_IDENTIFIERS = {"self", "true", "false", "none", "null"}


def tracked_files(root: pathlib.Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [p for p in out.stdout.decode().split("\0") if p]


class Repo:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.files = tracked_files(root)
        self.rust = [f for f in self.files if f.endswith(".rs")]
        self.modules = {}
        for f in self.rust:
            parts = f.split("/")
            self.modules.setdefault(parts[-1][:-3], []).append(f)
            for directory in parts[:-1]:
                self.modules.setdefault(directory, []).append(f)
        self.model_words = set()
        for f in self.files:
            if f.startswith("docs/model/") and f.endswith(".tla"):
                self.model_words |= self.words(f)

    def resolve(self, path: str) -> list[str]:
        """Tracked files whose path ends with `path` on a directory boundary."""
        path = path.lstrip("./")
        return [f for f in self.files if f == path or f.endswith("/" + path)]

    @functools.lru_cache(maxsize=None)
    def words(self, path: str) -> frozenset[str]:
        text = (self.root / path).read_text(errors="replace")
        if path.endswith(".rs"):
            text = strip_rust(text)
        return frozenset(re.findall(SEGMENT, text))

    @functools.lru_cache(maxsize=None)
    def all_members(self) -> dict[str, set[str]]:
        found: dict[str, set[str]] = {}
        for path in self.rust:
            for name, members in self.index(path).members.items():
                found.setdefault(name, set()).update(members)
        return found

    @functools.lru_cache(maxsize=None)
    def index(self, path: str) -> "Index":
        text = (self.root / path).read_text(errors="replace")
        return Index(strip_rust(text), text)


COMMENTS = re.compile(
    r"""//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^\\'\n])'""", re.S)
DEFINITION = re.compile(r"\b(?:fn|struct|enum|trait|type|const|static|mod|union)\s+(" + SEGMENT + ")")
BLOCK = re.compile(r"\b(impl|trait|enum|struct)\b([^{};]*)\{")


def strip_rust(text: str) -> str:
    """The code of a Rust file: no comments, string literals or char literals."""
    return COMMENTS.sub(" ", text)


def block_end(text: str, start: int) -> int:
    depth = 0
    for position in range(start, len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return position
    return len(text)


class Index:
    """What a stripped Rust file defines: names, and the members of each type."""

    def __init__(self, code: str, text: str = ""):
        self.defined = set(DEFINITION.findall(code))
        # Words inside string literals: wire values such as `allow_once`.
        self.values = set(re.findall(SEGMENT, " ".join(re.findall(r'"(?:\\.|[^"\\])*"', text))))
        self.members: dict[str, set[str]] = {}
        for match in BLOCK.finditer(code):
            keyword, header = match.group(1), match.group(2)
            if keyword == "impl":
                header = re.sub(r"^\s*<[^>]*(?:<[^>]*>[^>]*)*>", "", header)
                target = header.split(" for ")[-1]
            else:
                target = header
            name = re.search(r"(" + SEGMENT + r")\s*(?:<|where|:|$)", target.strip() + " ")
            if not name:
                continue
            body = code[match.end(): block_end(code, match.end() - 1)]
            members = self.members.setdefault(name.group(1), set())
            members |= set(re.findall(SEGMENT, body)) if keyword in ("enum", "struct") else set(
                DEFINITION.findall(body))


def expand(token: str) -> list[str]:
    """`A::{b, c}` -> `A::b`, `A::c`."""
    match = BRACES.search(token)
    if not match:
        return [token]
    out = []
    for alt in match.group(1).split(","):
        out += expand(token[: match.start()] + alt.strip() + token[match.end():])
    return out


def classify(token: str):
    """('file', path) | ('ident', segments) | None for a backticked token."""
    token = token.strip().rstrip(",;:")
    token = re.sub(r"\(\)$", "", token)
    if token.endswith(FILE_EXTENSIONS) and re.fullmatch(r"[A-Za-z0-9_./-]+", token):
        return ("file", token)
    if not re.fullmatch(f"{SEGMENT}(::{SEGMENT})*", token):
        return None
    segments = token.split("::")
    if len(segments) == 1:
        word = segments[0]
        if word in NOT_IDENTIFIERS:
            return None
        snake = "_" in word and word == word.lower()
        camel = word[0].isupper() and not word.isupper() and re.search(r"[a-z]", word)
        if not (snake or camel):
            return None
    return ("ident", segments)


RS_FILE = re.compile(r"`[^`\n]*\.rs`")
AFTER_FILE = re.compile(r"`([^`\n]*\.rs)`\s+`([a-z][a-z0-9]*)`")


UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
TABLE_LINE = re.compile(r" {0,3}\|")


def split_cells(line: str) -> list[str]:
    """The cells of a table line: split at every unescaped `|`, whatever the spaces
    around it, without the outer pipes; `\\|` is a pipe inside a cell."""
    body = line.strip()
    body = body[1:] if body.startswith("|") else body
    body = body[:-1] if body.endswith("|") and not body.endswith("\\|") else body
    return [cell.strip().replace("\\|", "|") for cell in UNESCAPED_PIPE.split(body)]


def table_rows(readme: pathlib.Path):
    """(table id, line number, text of the code cell or None, problem or None) for each
    row of each code table. A table that cites `.rs` files whose last header is not a
    code header, and a row with fewer cells than its header, come with a problem."""
    code_column = None
    columns = 0
    previous_blank = True
    table = 0
    header_line = 0
    unrecognized = False
    for number, line in enumerate(readme.read_text().splitlines(), 1):
        if not TABLE_LINE.match(line):
            if unrecognized:
                yield table, header_line, None, (
                    "this table cites .rs files, but its last column header "
                    "does not say code, Rust or mapping, so it is not checked")
            code_column, previous_blank, unrecognized = None, not line.strip(), False
            continue
        cells = split_cells(line)
        if all(re.fullmatch(r":?-{1,}:?", cell) for cell in cells):
            continue
        if previous_blank:  # the header row of a new table
            previous_blank = False
            table += 1
            header_line = number
            columns = len(cells)
            code_column = len(cells) - 1 if re.search(r"code|rust|mapping", cells[-1], re.I) else None
            continue
        if code_column is not None:
            if len(cells) < columns:
                yield table, number, None, (
                    f"row has {len(cells)} cells but the table header has {columns}; "
                    "a row that cannot be read is not checked, so it is rejected")
            else:
                yield table, number, " | ".join(cells[code_column:]), None
        elif RS_FILE.search(line):
            unrecognized = True
    if unrecognized:
        yield table, header_line, None, (
            "this table cites .rs files, but its last column header "
            "does not say code, Rust or mapping, so it is not checked")


def crate_of(path: str) -> str | None:
    parts = path.split("/")
    return "/".join(parts[:2]) if parts[0] == "crates" and len(parts) > 2 else None


def check(repo: Repo, readme: pathlib.Path) -> list[str]:
    errors = []
    checked: dict[int, int] = {}
    where = readme.name
    for table, number, line, problem in table_rows(readme):
        if problem:
            errors.append(f"{where}:{number}: {problem}")
            continue
        checked.setdefault(table, 0)
        tokens = []
        for raw in CODE.findall(line):
            for token in expand(raw):
                kind = classify(token)
                if kind:
                    tokens.append(kind)
        files, crates, directories = [], set(CRATE.findall(line)), set()
        for kind, value in tokens:
            if kind != "file":
                continue
            found = repo.resolve(value)
            if not found:
                errors.append(f"{where}:{number}: no tracked file matches `{value}`")
            files += found
            if "/" in value:
                directories.add(value.rsplit("/", 1)[0])
        scope = set(files)
        modules = set()
        for kind, value in tokens:  # `module::item`: the module is a file or directory
            if kind == "ident" and len(value) > 1 and value[0] in repo.modules:
                modules |= set(repo.modules[value[0]])
        scope |= modules
        files = files + sorted(modules)
        roots = {f"crates/{c}/" for c in crates} | {crate_of(f) + "/" for f in files if crate_of(f)}
        for root in roots:
            scope |= {f for f in repo.rust if f.startswith(root)}
        for directory in directories:
            scope |= {f for f in repo.rust if ("/" + directory + "/") in ("/" + f)}
        cited = bool(files or crates)
        if not scope:
            scope = set(repo.rust)
        rust = sorted(f for f in scope if f.endswith(".rs"))
        known = set()
        defined = set()
        values = set()
        members: dict[str, set[str]] = {}
        for path in rust:
            known |= repo.words(path)
            index = repo.index(path)
            defined |= index.defined
            values |= index.values
            for name, found in index.members.items():
                members.setdefault(name, set()).update(found)
        place = (f"the {len(rust)} Rust files of the crates cited in the row" if cited else "any Rust source")
        for file_token, name in AFTER_FILE.findall(line):
            resolved = [f for f in repo.resolve(file_token) if f.endswith(".rs")]
            checked[table] += 1
            if resolved and not any(name in repo.index(f).defined for f in resolved):
                errors.append(f"{where}:{number}: `{file_token}` does not define `fn {name}`")
        for kind, value in tokens:
            if kind != "ident" or (len(value) == 1 and value[0] in repo.model_words):
                continue
            checked[table] += 1
            text = "::".join(value)
            if len(value) == 1:
                name = value[0]
                if name in defined or name in known or name in values:
                    continue
                if name[0].isupper() and name in repo.all_members():  # a type of a crate the row does not cite
                    continue
                errors.append(f"{where}:{number}: `{text}` is not in {place}")
                continue
            names = value[1:] if value[0] in repo.modules else value
            if value[0] in repo.modules and len(names) == 1:
                if names[0] not in defined and names[0] not in known:
                    errors.append(f"{where}:{number}: `{text}`: `{names[0]}` is not in {place}")
                continue
            owner, member = names[-2], names[-1]
            if owner in repo.model_words:
                continue
            if member not in members.get(owner, set()):
                # A row can name a type of a crate it does not cite: look everywhere.
                if member in repo.all_members().get(owner, set()):
                    continue
            if owner not in members and owner not in known and owner not in repo.all_members():
                errors.append(f"{where}:{number}: `{text}`: `{owner}` is not in {place}")
            elif member not in members.get(owner, set()):
                errors.append(f"{where}:{number}: `{text}`: no `impl`, `trait`, `enum` or `struct` of "
                              f"`{owner}` in {place} has `{member}`")
    if not checked:
        errors.append(f"{readme}: no code table found; the parser no longer matches the README")
    for table, count in checked.items():
        if count == 0:
            errors.append(f"{readme}: table {table} yields no checkable name; the parser no longer matches it")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    root = pathlib.Path(__file__).resolve().parents[1]
    parser.add_argument("--root", type=pathlib.Path, default=root)
    parser.add_argument("--readme", type=pathlib.Path)
    args = parser.parse_args()
    readme = args.readme or args.root / "docs/model/README.md"
    errors = check(Repo(args.root), readme)
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print(f"check-model-locations: {len(errors)} stale reference(s); fix the table or the code",
              file=sys.stderr)
        return 1
    print("check-model-locations: every cited file, function and member is defined where the row says")
    return 0


if __name__ == "__main__":
    sys.exit(main())
