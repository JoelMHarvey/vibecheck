"""Function length, branchiness and duplicated blocks, from source text alone.

Python is measured with the ast module, exactly. JavaScript and TypeScript are
measured by matching braces from each function's opening line, which is
approximate (a brace in a string can throw it off) and good enough to find
outliers, which is all these are for: the 300-line handler, the function with
40 branches, the block pasted into six files.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

BRANCH_PY = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith,
             ast.BoolOp, ast.IfExp, ast.ExceptHandler, ast.comprehension)
BRANCH_JS = re.compile(r"\b(if|for|while|case|catch)\b|&&|\|\||\?\?|\?(?!\.)")
JS_FUNC = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\("
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?"
    r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::[^=]+)?=>\s*\{"
    r"|^\s*(?:public\s+|private\s+|protected\s+|static\s+|async\s+)*([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?::\s*[^={;]+)?\{\s*$",
    re.M)
JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "function", "else", "do", "with"}
JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue")


@dataclass
class Func:
    path: str
    line: int
    name: str
    length: int
    branches: int


def python_functions(path: str, text: str) -> List[Func]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            branches = sum(1 for n in ast.walk(node) if isinstance(n, BRANCH_PY) and n is not node)
            out.append(Func(path, node.lineno, node.name, end - node.lineno + 1, branches))
    return out


def js_functions(path: str, text: str) -> List[Func]:
    out = []
    for m in JS_FUNC.finditer(text):
        name = next((g for g in m.groups() if g), "anonymous")
        if name in JS_KEYWORDS:
            continue
        start = text.find("{", m.start())
        if start < 0:
            continue
        depth, i, n = 0, start, len(text)
        while i < n:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            continue
        body = text[start:i]
        first = text.count("\n", 0, m.start()) + 1
        length = body.count("\n") + 1
        out.append(Func(path, first, name, length, len(BRANCH_JS.findall(body))))
    return out


def functions(path: str, text: str) -> List[Func]:
    if path.endswith(".py"):
        return python_functions(path, text)
    if path.endswith(JS_EXTS):
        return js_functions(path, text)
    return []


_TRIVIAL = re.compile(r"^[\s{}()\[\];,]*$|^(import|from|export \{|export \*|#include|using|package)\b|^//|^#|^\*|^/\*")


def _normal_lines(text: str) -> List[Tuple[int, str]]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = re.sub(r"\s+", " ", line.strip())
        if len(s) < 6 or _TRIVIAL.match(s):
            continue
        out.append((i, s))
    return out


def duplicated_blocks(files: Dict[str, str], window: int = 8, max_lines: int = 300_000) -> Tuple[int, int, List[str]]:
    """(duplicated lines, total meaningful lines, examples) over every file.

    A block is ``window`` meaningful lines in a row (blank lines, braces and
    imports don't count) that appear somewhere else too. Each duplicated line
    counts once however many copies it has."""
    seen: Dict[str, Tuple[str, int]] = {}
    dup_lines: Dict[str, set] = {}
    examples: List[str] = []
    total = 0
    for path, text in files.items():
        lines = _normal_lines(text)
        total += len(lines)
        if total > max_lines:
            break
        for k in range(len(lines) - window + 1):
            chunk = "\n".join(s for _i, s in lines[k:k + window])
            h = hashlib.sha1(chunk.encode("utf-8")).hexdigest()
            here = (path, lines[k][0])
            first = seen.get(h)
            if first is None:
                seen[h] = here
                continue
            if first[0] == path and abs(first[1] - here[1]) < window:
                continue   # overlapping windows of one repeated run
            marks = dup_lines.setdefault(path, set())
            before = len(marks)
            marks.update(i for i, _s in lines[k:k + window])
            if len(examples) < 5 and before == 0:
                examples.append(f"{path}:{here[1]} repeats {first[0]}:{first[1]}")
    return sum(len(v) for v in dup_lines.values()), total, examples


def long_and_complex(funcs: Iterable[Func], max_length: int, max_branches: int) -> Tuple[List[Func], List[Func]]:
    funcs = list(funcs)
    long_ = sorted((f for f in funcs if f.length > max_length), key=lambda f: -f.length)
    complex_ = sorted((f for f in funcs if f.branches > max_branches), key=lambda f: -f.branches)
    return long_, complex_
