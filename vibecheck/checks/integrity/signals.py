"""Every integrity signal, read from a Repo (and optionally the live site).

Each signal either adds a finding (from rules.RULES) or a pass (rules.PASSES).
They look for presence and wiring, not volume.
"""

from __future__ import annotations

import json
import re
from typing import Callable, List, Optional, Sequence

from ...core.models import Finding
from . import code
from .repo import LOCKFILES, Repo
from .patterns import *  # noqa: F401,F403  (the tables)
from .rules import PASSES, RULES

def summarise(items: Sequence[str], n: int = 5) -> str:
    items = list(dict.fromkeys(items))
    head = "; ".join(items[:n])
    return head + (f"; and {len(items) - n} more" if len(items) > n else "")


class Collector:
    def __init__(self):
        self.findings: List[Finding] = []

    def add(self, rule_id: str, path: str, excerpt: str, line: int = 0) -> None:
        r = RULES[rule_id]
        fill = {"path": path, "excerpt": excerpt}
        self.findings.append(Finding(
            id=rule_id, check_id="integrity", category=r.category, severity=r.severity, title=r.title,
            why_it_matters=r.description.format(**fill), evidence=excerpt,
            fix_prompt=r.fix_prompt.format(**fill), verify_hint=r.verify, guide_url=r.guide, path=path, line=line))

    def ok(self, pass_id: str, evidence: str) -> None:
        title, category = PASSES[pass_id]
        self.findings.append(Finding(id=pass_id, check_id="integrity", category=category, severity="pass",
                                     title=title, evidence=evidence))


def has_server(repo: Repo) -> bool:
    return bool(repo.has(SERVER_HINTS)) or bool(repo.has_dep(*SERVER_DEPS))


def stack(repo: Repo) -> List[str]:
    found = [label for dep, label in FRAMEWORKS if repo.has_dep(dep)]
    # React and Vite are noise next to a framework built on them.
    if any(x in found for x in ("Next.js", "Remix", "Astro", "Expo", "React Native")):
        found = [f for f in found if f not in ("React", "Vite")]
    if any(x in found for x in ("Nuxt",)):
        found = [f for f in found if f != "Vue"]
    if "SvelteKit" in found:
        found = [f for f in found if f not in ("Svelte", "Vite")]
    readme = "\n".join(repo.texts.get(p, "")[:4000] for p in repo.has(r"^readme(\.\w+)?$"))
    blob = "\n".join(repo.paths) + "\n" + "\n".join("dep:" + d for d in sorted(repo.deps())) + "\n" + readme
    builders = [label for rx, label in BUILDERS if re.search(rx, blob, re.I | re.M)]
    return found + [f"built with {b}" for b in builders]


# ---- observability ------------------------------------------------------------

def observability(repo: Repo, c: Collector, server: bool) -> None:
    trackers = sorted({label for dep, label in ERROR_TRACKERS.items() if repo.has_dep(dep)})
    inits = repo.grep(TRACKER_INIT, files=repo.source_files)
    if trackers and inits:
        c.ok("obs-error-tracking", f"{', '.join(trackers)}, started in {inits[0][0]}")
    elif trackers:
        c.add("obs-error-tracking-not-initialised", "package.json", ", ".join(trackers))
    elif inits:
        c.ok("obs-error-tracking", f"started in {inits[0][0]}")
    else:
        c.add("obs-no-error-tracking", "/", "no Sentry, OpenTelemetry, Datadog or similar SDK")

    loggers = repo.has_dep(*LOGGERS)
    if loggers:
        c.ok("obs-structured-logging", ", ".join(loggers))
    elif server:
        c.add("obs-no-structured-logging", "/", "no structured logger in the dependencies")

    if server:
        paths = repo.has(HEALTH_PATH)
        routes = [] if paths else repo.grep(HEALTH_ROUTE, files=repo.source_files, limit=1)
        if paths or routes:
            c.ok("obs-health-endpoint", paths[0] if paths else f"{routes[0][0]}:{routes[0][1]}")
        else:
            c.add("obs-no-health-endpoint", "/", "no /health or /api/health route found")

    public_maps = []
    for rel in repo.has(r"(^|/)next\.config\.[cm]?[jt]s$"):
        if re.search(r"productionBrowserSourceMaps\s*:\s*true", repo.texts.get(rel, "")):
            public_maps.append(f"{rel} (productionBrowserSourceMaps: true)")
    for rel in repo.has(r"(^|/)vite\.config\.[cm]?[jt]s$"):
        if re.search(r"sourcemap\s*:\s*true", repo.texts.get(rel, "")):
            public_maps.append(f"{rel} (build.sourcemap: true)")
    if public_maps:
        c.add("obs-sourcemaps-public", public_maps[0].split(" ")[0], summarise(public_maps))


def live(url: str, fetch: Callable, c: Collector) -> None:
    """URL signals: does a health route answer, is a status page linked."""
    base = url.rstrip("/")
    for path in ("/api/health", "/health", "/healthz"):
        r = fetch(base + path)
        if r is not None and 200 <= getattr(r, "status", 0) < 300:
            c.ok("obs-health-responding", f"{path} answered {r.status}")
            break
    else:
        c.add("obs-health-not-responding", "/api/health", "/api/health, /health and /healthz didn't answer 200")
    home = fetch(base + "/")
    text = getattr(home, "text", "") if home is not None else ""
    m = re.search(r"""href=["']([^"']*(?://status\.|/status\b)[^"']*)["']""", text or "", re.I)
    if m:
        c.ok("obs-status-page", m.group(1))


# ---- alerting --------------------------------------------------------------------

def alerting(repo: Repo, c: Collector, server: bool) -> None:
    found = []
    deps = repo.has_dep(*ALERT_DEPS)
    if deps:
        found.append(", ".join(deps))
    paths = repo.has(ALERT_PATH)
    if paths:
        found.append(paths[0])
    if not found:
        hits = repo.grep(ALERT_TEXT, files=repo.source_files + repo.ci_files, limit=1)
        if hits:
            found.append(f"{hits[0][0]}:{hits[0][1]}")
    if found:
        c.ok("alert-configured", summarise(found, 3))
    elif server:
        c.add("alert-none", "/", "no uptime monitor, alert rule or paging integration found")

    runbooks = repo.has(RUNBOOK_PATH)
    if runbooks:
        c.ok("alert-runbook", runbooks[0])
    elif server:
        c.add("alert-no-runbook", "/", "no RUNBOOK, INCIDENT or ON-CALL document")


# ---- how it was built --------------------------------------------------------

def build(repo: Repo, c: Collector) -> None:
    s = stack(repo)
    if s:
        c.ok("build-stack", ", ".join(s))

    readers = repo.grep(ENV_READ, files=repo.source_files, limit=3)
    if readers:
        examples = repo.has(ENV_EXAMPLE)
        if examples:
            c.ok("build-env-example", examples[0])
        else:
            c.add("build-no-env-example", "/", summarise([f"{p}:{n}" for p, n in readers], 3))

    schemas = [p for p in repo.has(SCHEMA_PATH) if not p.endswith("models.py") or
               re.search(r"from django\.db import models|declarative_base|DeclarativeBase|SQLModel", repo.texts.get(p, ""))]
    if schemas:
        migrations = repo.has(MIGRATION_PATH)
        if migrations:
            c.ok("build-migrations", migrations[0].rsplit("/", 1)[0] + "/")
        else:
            c.add("build-no-migrations", schemas[0], ", ".join(schemas[:3]))

    names = repo.names()
    if repo.package_jsons:
        locks = sorted(names & LOCKFILES)
        if locks:
            c.ok("build-lockfile", ", ".join(locks))
        else:
            c.add("build-no-lockfile", "package.json", "package.json")
        floating = []
        for rel, pkg in repo.package_jsons.items():
            for key in ("dependencies", "devDependencies"):
                for name, ver in (pkg.get(key) or {}).items():
                    if isinstance(ver, str) and ver.strip() in ("*", "latest", "x", ""):
                        floating.append(f"{name}@{ver.strip() or 'empty'}")
        if floating:
            c.add("build-floating-versions", "package.json", summarise(floating))
    elif repo.py_deps and any(n in names for n in ("pyproject.toml",)) and \
            re.search(r"\[tool\.(poetry|uv|pdm)\]", "\n".join(repo.texts.get(p, "") for p in repo.has(r"(^|/)pyproject\.toml$"))):
        locks = sorted(names & LOCKFILES)
        if locks:
            c.ok("build-lockfile", ", ".join(locks))
        else:
            c.add("build-no-lockfile", "pyproject.toml", "pyproject.toml")

    deploy = repo.has(DEPLOY_PATH)
    if deploy:
        c.ok("build-deploy-config", summarise(deploy, 3))
    else:
        c.add("build-no-deploy-config", "/", "no vercel.json, Dockerfile, fly.toml or similar")


# ---- tests -------------------------------------------------------------------------

def _ci_runs(repo: Repo, command: str) -> List[str]:
    out = []
    for rel in repo.ci_files:
        text = repo.texts.get(rel, "")
        if re.search(CI_TRIGGERS, text) and re.search(command, text, re.I):
            out.append(rel)
            continue
        # A workflow that calls a script that runs the tests: npm run ci, make check.
        for script in re.findall(r"\b(?:npm|pnpm|yarn|bun)\s+run\s+([\w:-]+)", text):
            for pkg in repo.package_jsons.values():
                body = str((pkg.get("scripts") or {}).get(script, ""))
                if re.search(command, body, re.I) and re.search(CI_TRIGGERS, text):
                    out.append(rel)
                    break
    return sorted(set(out))


def tests(repo: Repo, c: Collector) -> None:
    test_files = repo.test_files
    source = repo.source_files
    if not test_files:
        c.add("tests-none", "/", f"no test files among {len(source)} source files")
        return
    c.ok("tests-present", f"{len(test_files)} test file{'s' if len(test_files) != 1 else ''}")

    running = _ci_runs(repo, TEST_CMD)
    if running:
        c.ok("tests-in-ci", summarise(running, 3))
    elif repo.ci_files:
        c.add("tests-not-in-ci", repo.ci_files[0], "no CI workflow runs them: " + summarise(repo.ci_files, 3))
    else:
        c.add("tests-not-in-ci", "/", "there's no CI workflow at all")

    if len(source) >= FEW_TESTS_MIN_SOURCE and len(test_files) / max(len(source), 1) < FEW_TESTS_RATIO:
        c.add("tests-few", "/", f"{len(test_files)} test files for {len(source)} source files")

    web = any(x in stack(repo) for x in ("Next.js", "Remix", "SvelteKit", "Nuxt", "Astro", "Vite", "React",
                                          "Vue", "Svelte", "Flask", "Django", "Streamlit"))
    e2e = repo.has_dep(*E2E_DEPS) or repo.has(r"(^|/)(playwright|cypress)\.config\.[cm]?[jt]s$")
    if e2e:
        c.ok("tests-e2e", summarise(e2e, 3))
    elif web:
        c.add("tests-no-e2e", "/", "no Playwright, Cypress or similar")

    blob = "\n".join(repo.texts.get(p, "") for p in repo.paths
                     if re.search(r"(package\.json|vitest\.config|jest\.config|pyproject\.toml|setup\.cfg|"
                                  r"\.coveragerc|tox\.ini|\.ya?ml)$", p))
    if re.search(COVERAGE, blob) or repo.has(r"(^|/)\.coveragerc$|codecov\.ya?ml$"):
        c.ok("tests-coverage", "coverage is configured")
    else:
        c.add("tests-no-coverage", "/", "no coverage configuration")


# ---- code quality --------------------------------------------------------------

def _pkg_has(repo: Repo, key: str) -> bool:
    return any(key in pkg for pkg in repo.package_jsons.values())


def _tsconfig_strict(repo: Repo, rel: str, depth: int = 0) -> Optional[bool]:
    text = repo.texts.get(rel)
    if text is None or depth > 3:
        return None
    clean = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)
    clean = re.sub(r",(\s*[}\]])", r"\1", clean)
    try:
        cfg = json.loads(clean)
    except ValueError:
        m = re.search(r'"strict"\s*:\s*(true|false)', text)
        return (m.group(1) == "true") if m else None
    strict = (cfg.get("compilerOptions") or {}).get("strict")
    if strict is not None:
        return bool(strict)
    base = cfg.get("extends")
    if isinstance(base, str) and base.startswith("."):
        parent = (rel.rsplit("/", 1)[0] + "/" if "/" in rel else "") + base.lstrip("./")
        parent = parent if parent.endswith(".json") else parent + ".json"
        return _tsconfig_strict(repo, parent, depth + 1)
    if isinstance(base, str) and "strict" in base:   # @tsconfig/strictest and friends
        return True
    return None


def quality(repo: Repo, c: Collector) -> None:
    linters = repo.has(LINTER_PATH)
    py_lint = re.search(r"\[tool\.(ruff|pylint|flake8)", "\n".join(repo.texts.get(p, "") for p in repo.has(r"(^|/)(pyproject\.toml|setup\.cfg)$")))
    js_lint = _pkg_has(repo, "eslintConfig") or repo.has_dep("eslint", "@biomejs/biome", "oxlint", "ruff", "flake8", "pylint")
    if linters or py_lint or js_lint:
        c.ok("quality-linter", linters[0] if linters else ("pyproject.toml" if py_lint else "package.json"))
        if repo.ci_files:
            running = _ci_runs(repo, LINT_CMD)
            if running:
                c.ok("quality-lint-in-ci", summarise(running, 3))
            else:
                c.add("quality-lint-not-in-ci", repo.ci_files[0], "no CI step runs the linter")
    elif repo.source_files:
        c.add("quality-no-linter", "/", "no ESLint, Biome, Ruff or similar configuration")

    formatters = repo.has(FORMATTER_PATH)
    py_fmt = re.search(r"\[tool\.(black|ruff)", "\n".join(repo.texts.get(p, "") for p in repo.has(r"(^|/)pyproject\.toml$")))
    if formatters or py_fmt or _pkg_has(repo, "prettier") or repo.has_dep("prettier", "@biomejs/biome", "black"):
        c.ok("quality-formatter", formatters[0] if formatters else "configured")
    elif repo.source_files:
        c.add("quality-no-formatter", "/", "no Prettier, Biome, Black or Ruff format configuration")

    roots = [p for p in repo.has(r"(^|/)tsconfig\.json$") if p.count("/") <= 2]
    if roots:
        loose = [p for p in roots if _tsconfig_strict(repo, p) is not True]
        if loose:
            c.add("quality-ts-not-strict", loose[0], summarise(loose, 3))
        else:
            c.ok("quality-ts-strict", summarise(roots, 3))

    funcs = []
    src = {p: repo.texts[p] for p in repo.source_files if p in repo.texts}
    for rel, text in src.items():
        funcs.extend(code.functions(rel, text))
    long_, complex_ = code.long_and_complex(funcs, LONG_FUNCTION, COMPLEX_FUNCTION)
    if long_:
        c.add("quality-long-functions", long_[0].path,
              summarise([f"{f.name} in {f.path}:{f.line} ({f.length} lines)" for f in long_]), long_[0].line)
    if complex_:
        c.add("quality-complex-functions", complex_[0].path,
              summarise([f"{f.name} in {f.path}:{f.line} ({f.branches} branches)" for f in complex_]), complex_[0].line)

    dup, total, examples = code.duplicated_blocks(src)
    if total and dup / total >= DUPLICATION_SHARE and dup >= 40:
        c.add("quality-duplication", examples[0].split(":")[0] if examples else "/",
              f"{dup} of {total} meaningful lines ({dup * 100 // total}%) are copies of blocks elsewhere; "
              + summarise(examples, 3))


# ---- tech debt -------------------------------------------------------------------

def debt(repo: Repo, c: Collector) -> None:
    src = [p for p in repo.source_files if p in repo.texts]
    lines = sum(repo.lines_of(p) for p in src)
    todo_files = []
    todos = 0
    for p in src:
        n = len(re.findall(r"\b(TODO|FIXME|HACK|XXX)\b", repo.texts[p]))
        if n:
            todos += n
            todo_files.append((n, p))
    if lines >= 1000 and todos * 1000 / lines > TODO_PER_KLOC:
        top = ", ".join(f"{p} ({n})" for n, p in sorted(todo_files, reverse=True)[:3])
        c.add("debt-todo-density", sorted(todo_files, reverse=True)[0][1],
              f"{todos} TODO/FIXME/HACK comments in {lines:,} lines of source; most in {top}")

    large = sorted(((repo.lines_of(p), p) for p in src if repo.lines_of(p) > LARGE_FILE), reverse=True)
    if large:
        c.add("debt-large-files", large[0][1], summarise([f"{p} ({n:,} lines)" for n, p in large]))

    leftovers = [p for p in repo.has(LEFTOVER) if not p.startswith((".git/",))]
    if leftovers:
        c.add("debt-leftover-files", leftovers[0], summarise(leftovers))
