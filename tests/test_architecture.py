"""Integrity phase B: the architecture read. Claude is never called; a fake
architect or a fake SDK client stands in."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_integrity import WELL_BUILT, write  # noqa: E402

from vibecheck.checks.integrity import CHECK  # noqa: E402
from vibecheck.checks.integrity import architecture as arch  # noqa: E402
from vibecheck.checks.integrity.repo import from_files  # noqa: E402
from vibecheck.checks.integrity.rules import RULES  # noqa: E402
from vibecheck.core.models import Context, Target  # noqa: E402

WEBHOOK = ("export async function POST(req: Request) {\n"
           "  const event = JSON.parse(await req.text());\n"
           "  await db.payment.update({ where: { id: event.id }, data: { paid: true } });\n"
           "  return Response.json({ ok: true });\n}\n")
FILES = dict(WELL_BUILT, **{"src/app/api/webhooks/stripe/route.ts": WEBHOOK,
                            "src/lib/config.ts": 'export const key = "sk_live_abcdefghijklmnopqrstuv";\n'})


class FakeArchitect:
    def __init__(self, answer=None, exc=None):
        self.answer, self.exc, self.messages = answer, exc, []
        self.last_cached = False

    def review(self, message):
        self.messages.append(message)
        if self.exc:
            raise self.exc
        return self.answer


def problem(kind="unverified-webhook", path="src/app/api/webhooks/stripe/route.ts",
            quote="const event = JSON.parse(await req.text());", note="Anyone can post a fake payment. Verify it."):
    return {"kind": kind, "path": path, "quote": quote, "note": note}


def run(files, architect):
    with write(files) as d:
        return CHECK.run(Target(repo=d), Context(guard=False, options={"architecture": architect}))


class DigestTest(unittest.TestCase):
    def test_boundary_code_first_and_secrets_redacted(self):
        msg, sent = arch.digest(from_files(list(FILES.items())))
        self.assertLess(msg.index("webhooks/stripe/route.ts ==="), msg.index("src/lib/config.ts ==="))
        self.assertNotIn("sk_live_abcdefghijklmnopqrstuv", msg)
        self.assertIn("[redacted]", msg)
        self.assertNotIn(".env.example ===", msg)
        self.assertIn("src/app/api/webhooks/stripe/route.ts", sent)

    def test_capped(self):
        big = {f"src/lib/f{i}.ts": "export const x = 1;\n" * 2000 for i in range(40)}
        msg, sent = arch.digest(from_files(list(big.items())))
        self.assertLessEqual(len(msg), arch.MAX_DIGEST_CHARS + 2000)
        self.assertTrue(all(len(t) <= arch.MAX_FILE_CHARS for t in sent.values()))


class GroundingTest(unittest.TestCase):
    def setUp(self):
        _msg, self.sent = arch.digest(from_files(list(FILES.items())))

    def test_a_real_quote_gets_its_line_from_us(self):
        (f,) = arch.ground({"findings": [problem()]}, self.sent)
        self.assertEqual((f["rule"], f["line"]), ("arch-unverified-webhook", 2))

    def test_invented_quotes_unknown_files_and_unknown_kinds_are_dropped(self):
        answer = {"findings": [problem(quote="stripe.webhooks.constructEvent(body, sig, secret)"),
                               problem(path="src/not/sent.ts"), problem(kind="vibes"), problem(quote="short")]}
        self.assertEqual(arch.ground(answer, self.sent), [])

    def test_at_most_eight(self):
        self.assertEqual(len(arch.ground({"findings": [problem()] * 20}, self.sent)), arch.MAX_FINDINGS)


class InTheCheckTest(unittest.TestCase):
    def test_grounded_problems_become_findings_with_a_line(self):
        r = run(FILES, FakeArchitect({"findings": [problem(), problem(quote="made up line that isn't there")]}))
        f = next(x for x in r.findings if x.id == "arch-unverified-webhook")
        self.assertEqual((f.severity, f.path, f.line), ("medium", "src/app/api/webhooks/stripe/route.ts", 2))
        self.assertIn("Verify it.", f.fix_prompt)
        self.assertIn("a model's review", f.why_it_matters)
        self.assertIn("1 problems, 1 dropped", r.meta["architecture"])

    def test_without_the_flag_nothing_is_sent(self):
        with write(FILES) as d:
            r = CHECK.run(Target(repo=d), Context(guard=False))
        self.assertNotIn("architecture", r.meta)

    def test_an_unavailable_review_changes_nothing_else(self):
        r = run(FILES, FakeArchitect(exc=arch.ReviewUnavailable("the review was declined")))
        self.assertIn("not run: the review was declined", r.meta["architecture"])
        self.assertFalse(any(f.id.startswith("arch-") for f in r.findings))

    def test_every_kind_has_a_rule(self):
        for rule_id in arch.KINDS.values():
            self.assertEqual(RULES[rule_id].category, "quality")


class ClaudeArchitectTest(unittest.TestCase):
    def client(self, text, stop="end_turn"):
        create = mock.Mock(return_value=SimpleNamespace(stop_reason=stop,
                                                        content=[SimpleNamespace(type="text", text=text)]))
        return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create))), create

    def test_request_shape_and_the_disk_cache(self):
        client, create = self.client(json.dumps({"findings": []}))
        with tempfile.TemporaryDirectory() as d:
            a = arch.ClaudeArchitect(client=client, cache_dir=d)
            self.assertEqual(a.review("digest"), {"findings": []})
            self.assertFalse(a.last_cached)
            a.review("digest")
            self.assertTrue(a.last_cached)
            self.assertEqual(create.call_count, 1)
        kw = create.call_args.kwargs
        self.assertEqual(kw["model"], "claude-opus-5-5")
        self.assertEqual(kw["output_config"]["format"]["schema"], arch.SCHEMA)
        self.assertEqual(kw["fallbacks"], "default")
        self.assertNotIn("temperature", kw)

    def test_refusal_and_bad_json_are_unavailable(self):
        for text, stop in (("", "refusal"), ("{", "max_tokens"), ("nope", "end_turn")):
            client, _ = self.client(text, stop)
            with tempfile.TemporaryDirectory() as d, self.subTest(stop), self.assertRaises(arch.ReviewUnavailable):
                arch.ClaudeArchitect(client=client, cache_dir=d).review("x")


class CliTest(unittest.TestCase):
    def test_needs_a_folder(self):
        from vibecheck.cli import main
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--visibility", "https://x.test", "--architecture"])


if __name__ == "__main__":
    unittest.main()
