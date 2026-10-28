"""One pass over a repository that every integrity signal reads from.

Walks with the shared walker (so .vibecheckignore and --exclude apply and
node_modules never does), keeps every path, and reads the text of the files
the signals look inside: manifests, configs, CI workflows and source.
Nothing here judges anything.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ...core.walker import read_text, walk

SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php",
               ".java", ".kt", ".rs", ".svelte", ".vue", ".astro", ".swift", ".cs"}
CONFIG_EXTS = {".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".md", ".txt", ".sql", ".prisma"}
CONFIG_NAMES = {"dockerfile", "procfile", "makefile", ".gitignore", ".env.example", ".env.sample",
                ".env.template", ".env.local.example", "example.env", ".nvmrc", ".python-version",
                ".eslintrc", ".prettierrc", ".editorconfig", "justfile", ".replit", ".coveragerc",
                ".flake8", ".pylintrc", "pipfile", "gemfile", "go.mod", "cargo.toml"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock",
             "npm-shrinkwrap.json", "poetry.lock", "uv.lock", "pipfile.lock", "pdm.lock",
             "cargo.lock", "go.sum", "gemfile.lock", "composer.lock"}

TEST_FILE = re.compile(
    r"(^|/)(tests?|__tests__|spec|e2e|cypress|playwright)/"
    r"|(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$|_spec\.rb$|(^|/)conftest\.py$",
    re.I)
GENERATED = re.compile(r"(\.generated\.|\.gen\.|/generated/|/migrations?/|\.d\.ts$|/__generated__/)", re.I)

CI_FILE = re.compile(r"^(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|\.circleci/config\.ya?ml"
                     r"|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.buildkite/[^/]+\.ya?ml"
                     r"|\.drone\.ya?ml|\.woodpecker\.ya?ml|vercel\.json|netlify\.toml)$", re.I)

MAX_READ_FILES = 6000


@dataclass
class Repo:
    label: str
    paths: List[str] = field(default_factory=list)       # every file, posix, relative
    texts: Dict[str, str] = field(default_factory=dict)  # rel -> text, for files we read
    npm_deps: Set[str] = field(default_factory=set)
    py_deps: Set[str] = field(default_factory=set)
    package_jsons: Dict[str, dict] = field(default_factory=dict)

    # -- what's there --------------------------------------------------------
    @property
    def lower_paths(self) -> List[str]:
        return [p.lower() for p in self.paths]

    def names(self) -> Set[str]:
        return {p.rsplit("/", 1)[-1].lower() for p in self.paths}

    def has(self, pattern: str) -> List[str]:
        """Paths matching a regex (case-insensitive)."""
        rx = re.compile(pattern, re.I)
        return [p for p in self.paths if rx.search(p)]

    def grep(self, pattern: str, files: Optional[Iterable[str]] = None, limit: int = 20) -> List[Tuple[str, int]]:
        """(path, line) of matches in the files we read."""
        rx = re.compile(pattern, re.I | re.M)
        out = []
        for rel in (files if files is not None else self.texts):
            text = self.texts.get(rel)
            if not text:
                continue
            m = rx.search(text)
            if m:
                out.append((rel, text.count("\n", 0, m.start()) + 1))
                if len(out) >= limit:
                    break
        return out

    def deps(self) -> Set[str]:
        return self.npm_deps | self.py_deps

    def has_dep(self, *names: str) -> List[str]:
        found = []
        for n in names:
            if n.endswith("*"):
                found += sorted(d for d in self.deps() if d.startswith(n[:-1]))
            elif n in self.deps():
                found.append(n)
        return found

    @property
    def source_files(self) -> List[str]:
        return [p for p in self.paths if _ext(p) in SOURCE_EXTS and not TEST_FILE.search(p)
                and not GENERATED.search(p) and not p.lower().endswith((".config.js", ".config.ts", ".config.mjs"))]

    @property
    def test_files(self) -> List[str]:
        return [p for p in self.paths if _ext(p) in SOURCE_EXTS and TEST_FILE.search(p)]

    @property
    def ci_files(self) -> List[str]:
        return [p for p in self.paths if CI_FILE.search(p) and p.split("/")[-1] not in ("vercel.json", "netlify.toml")]

    def ci_text(self) -> str:
        return "\n".join(self.texts.get(p, "") for p in self.ci_files)

    def lines_of(self, rel: str) -> int:
        t = self.texts.get(rel)
        return t.count("\n") + (1 if t and not t.endswith("\n") else 0) if t else 0


def _ext(p: str) -> str:
    name = p.rsplit("/", 1)[-1]
    return ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""


def _wanted(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].lower()
    ext = _ext(rel)
    return (ext in SOURCE_EXTS or ext in CONFIG_EXTS or name in CONFIG_NAMES
            or name.startswith((".eslintrc", ".prettierrc", "tsconfig", ".env.")) or CI_FILE.search(rel) is not None)


def _parse_deps(repo: Repo) -> None:
    for rel, text in repo.texts.items():
        name = rel.rsplit("/", 1)[-1].lower()
        if name == "package.json":
            try:
                pkg = json.loads(text)
            except ValueError:
                continue
            if not isinstance(pkg, dict):
                continue
            repo.package_jsons[rel] = pkg
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                deps = pkg.get(key)
                if isinstance(deps, dict):
                    repo.npm_deps.update(k.lower() for k in deps)
        elif re.match(r"requirements[^/]*\.(txt|in)$", name):
            for line in text.splitlines():
                m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if m and not line.lstrip().startswith(("#", "-")):
                    repo.py_deps.add(m.group(1).lower().replace("_", "-"))
        elif name in ("pyproject.toml", "pipfile", "setup.cfg"):
            # Good enough for presence: quoted names at the start of a requirement.
            for m in re.finditer(r"""^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[;"']|=\s*["{])""", text, re.M):
                repo.py_deps.add(m.group(1).lower().replace("_", "-"))


def from_folder(root: str, exclude: Sequence[str] = ()) -> Repo:
    base = Path(root)
    repo = Repo(label=base.name or str(base))
    read = 0
    for entry in walk(base, exclude=exclude):
        repo.paths.append(entry.rel)
        if entry.skipped or read >= MAX_READ_FILES or not _wanted(entry.rel):
            continue
        text = read_text(entry.path)
        if text is not None:
            repo.texts[entry.rel] = text
            read += 1
    # Lockfiles are skipped by the walker (not read) but still listed above.
    _parse_deps(repo)
    return repo


def from_files(files: Sequence[tuple], label: str = "uploaded project") -> Repo:
    repo = Repo(label=label)
    for rel, text in files:
        rel = str(rel).lstrip("/")
        repo.paths.append(rel)
        if _wanted(rel) and isinstance(text, str):
            repo.texts[rel] = text
    _parse_deps(repo)
    return repo
