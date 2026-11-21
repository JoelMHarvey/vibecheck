"""The error reporter sends nothing personal, and nothing at all without a DSN."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from server import app as server  # noqa: E402
from server import errorreport  # noqa: E402

# Made-up values, put together here so this repository's own scan does not
# read them as a real key and a real password.
FAKE_KEY = "sk_" + "live_abcdefghijklmnopqrstuvwxyz012345"
FAKE_PASSWORD = "-".join(["hunter2", "very", "secret"])

SECRETS = [
    "jane.doe@example.com", "203.0.113.7", "2001:db8::8a2e:370:7334",
    "My mother is ill and I need help", "07700900123", "4242424242424242",
    FAKE_KEY, "token=abc", "Jane Doe",
]


def sample_error():
    def handler():
        # locals that a careless reporter would attach
        password = FAKE_PASSWORD  # noqa: F841
        cookie = "session=abcdef"  # noqa: F841
        raise ValueError(
            "could not save note 'My mother is ill and I need help' for \"Jane Doe\" "
            "<jane.doe@example.com> from 203.0.113.7 / 2001:db8::8a2e:370:7334, phone 07700900123, "
            "card 4242424242424242, key " + FAKE_KEY + ", "
            "see https://example.com/reset?token=abc ; "
            "DETAIL: Key (email)=(jane.doe@example.com) already exists; column 'email' of relation \"users\"")
    try:
        handler()
    except ValueError as exc:
        return exc


class ScrubTest(unittest.TestCase):
    def test_event_carries_no_personal_data(self):
        event = errorreport.build_event(sample_error(), where="request", route="POST /notes/<int:id>", app="t")
        blob = json.dumps(event)
        for secret in SECRETS + ["hunter2", "session=abcdef"]:
            self.assertNotIn(secret, blob)
        value = event["exception"]["values"][0]
        self.assertEqual(value["type"], "ValueError")
        # quoted text goes whole, even a single word: it may be a name
        self.assertNotIn("'email'", value["value"])
        self.assertIn("[email]", value["value"])
        self.assertIn("[text]", value["value"])
        self.assertEqual(event["transaction"], "POST /notes/<int:id>")
        self.assertEqual(value["stacktrace"]["frames"][-1]["function"], "handler")

    def test_event_has_only_the_expected_fields(self):
        event = errorreport.build_event(sample_error(), app="t")
        self.assertLessEqual(set(event), {"event_id", "timestamp", "platform", "level", "logger",
                                          "environment", "tags", "exception", "transaction"})
        for banned in ("request", "user", "extra", "contexts", "breadcrumbs", "server_name", "modules"):
            self.assertNotIn(banned, event)
        for frame in event["exception"]["values"][0]["stacktrace"]["frames"]:
            self.assertEqual(set(frame), {"filename", "function", "lineno", "in_app"})
            self.assertNotIn(os.path.expanduser("~"), frame["filename"])

    def test_a_dumped_query_and_short_amounts_do_not_survive(self):
        message = ("\nInvalid `prisma.entry.create()` invocation:\n\n"
                   "{ data: { name: 'Tofu', payee: \"Jane\", amount: 1284.5, note: 'see you at 9' } }\n\n"
                   "Unique constraint failed on the fields: (`payee`), amount 284.50 on 2026-11-22 at 09:15")
        out = errorreport.scrub(message)
        for secret in ("Tofu", "Jane", "1284", "284.50", "see you", "2026", "09:15", "data:"):
            self.assertNotIn(secret, out)
        self.assertIn("`prisma.entry.create()`", out)
        self.assertIn("Unique constraint failed", out)
        self.assertEqual(errorreport.scrub("KeyError: 'Jane'"), "KeyError: [text]")

    def test_a_machine_code_is_kept_as_a_tag(self):
        exc = sample_error()
        exc.sqlstate = "23505"
        self.assertEqual(errorreport.build_event(exc, app="t")["tags"]["code"], "23505")
        exc.sqlstate = "Jane Doe said hello"
        self.assertNotIn("code", errorreport.build_event(exc, app="t")["tags"])

    def test_message_is_capped(self):
        self.assertLessEqual(len(errorreport.scrub("word " * 500)), errorreport.MAX_MESSAGE)


class DsnTest(unittest.TestCase):
    def test_nothing_is_sent_without_a_dsn(self):
        with mock.patch.dict(os.environ, {}, clear=False), \
                mock.patch("urllib.request.urlopen") as urlopen:
            os.environ.pop("SENTRY_DSN", None)
            self.assertFalse(errorreport.capture_exception(sample_error(), wait=True))
            urlopen.assert_not_called()

    def test_nothing_is_sent_with_a_malformed_dsn(self):
        for bad in ("", "not a url", "https://errors.example.test/3", "ftp://k@errors.example.test/3",
                    "https://k@errors.example.test/abc"):
            self.assertIsNone(errorreport.parse_dsn(bad))

    def test_a_dsn_sends_one_scrubbed_post(self):
        with mock.patch.dict(os.environ, {"SENTRY_DSN": "https://abc123@errors.example.test/7"}), \
                mock.patch("urllib.request.urlopen") as urlopen:
            errorreport._sent.clear()
            self.assertTrue(errorreport.capture_exception(sample_error(), where="cron:digest", wait=True))
            req = urlopen.call_args[0][0]
            self.assertEqual(req.full_url, "https://errors.example.test/api/7/store/")
            self.assertIn("sentry_key=abc123", req.get_header("X-sentry-auth"))
            body = req.data.decode()
            for secret in SECRETS:
                self.assertNotIn(secret, body)
            self.assertEqual(json.loads(body)["tags"]["where"], "cron:digest")

    def test_a_failing_tracker_never_raises(self):
        with mock.patch.dict(os.environ, {"SENTRY_DSN": "https://abc123@errors.example.test/7"}), \
                mock.patch("urllib.request.urlopen", side_effect=OSError("down")):
            errorreport._sent.clear()
            self.assertTrue(errorreport.capture_exception(sample_error(), wait=True))

    def test_a_flood_is_capped(self):
        with mock.patch.dict(os.environ, {"SENTRY_DSN": "https://abc123@errors.example.test/7"}), \
                mock.patch("urllib.request.urlopen") as urlopen:
            errorreport._sent.clear()
            results = [errorreport.capture_exception(sample_error(), wait=True) for _ in range(30)]
            self.assertEqual(sum(results), errorreport.MAX_EVENTS_PER_MINUTE)
            self.assertEqual(urlopen.call_count, errorreport.MAX_EVENTS_PER_MINUTE)


# What people submit to the scanner: a site's address and a repository's name.
SUBMITTED = ["staging.acme-corp.example", "acme-corp/payroll-internal", "acme-corp", "payroll-internal",
             "https://staging.acme-corp.example/admin?key=letmein", "letmein", "bücher.example"]


def scan_error():
    try:
        raise RuntimeError(
            "scan of https://staging.acme-corp.example/admin?key=letmein failed: could not resolve "
            "staging.acme-corp.example (bücher.example); repo 'acme-corp/payroll-internal' at "
            "github.com/acme-corp/payroll-internal.git answered 404 for field 'findings'")
    except RuntimeError as exc:
        return exc


def call(site, path, method="GET", query="", body=b""):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
               "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body), "REMOTE_ADDR": "203.0.113.7"}
    got = {}
    out = site(environ, lambda status, headers: got.update(status=status))
    return got["status"], b"".join(out)


class SendNow:
    """In place of the reporter's background thread, so the test sees the send."""

    def __init__(self, target, args=(), daemon=None):
        self.run = lambda: target(*args)

    def start(self):
        self.run()

    def join(self, timeout=None):
        pass


class CrashedFunctionTest(unittest.TestCase):
    """server/app.py reports a function that crashed, and nothing submitted goes with it."""

    DSN = {"SENTRY_DSN": "https://abc123@errors.example.test/7"}

    def setUp(self):
        self.site = server.Site()
        errorreport._sent.clear()

    def crash(self, url="/api/scan-url"):
        def boom(*a, **k):
            raise scan_error()
        return mock.patch.dict(self.site.functions, {url: type("handler", (), {"do_GET": boom, "do_POST": boom})})

    def test_a_submitted_address_or_repo_name_is_not_sent(self):
        with mock.patch.dict(os.environ, self.DSN), mock.patch("urllib.request.urlopen") as urlopen, \
                mock.patch("traceback.print_exc"), mock.patch("threading.Thread", SendNow), self.crash():
            status, body = call(self.site, "/api/scan-url", "POST", query="url=staging.acme-corp.example",
                                body=b'{"url": "https://staging.acme-corp.example/admin?key=letmein"}')
        self.assertTrue(status.startswith("500"))
        self.assertEqual(body, b"A server error has occurred\n")
        self.assertEqual(urlopen.call_count, 1)
        sent = urlopen.call_args[0][0].data.decode()
        for secret in SUBMITTED + ["203.0.113.7"]:
            self.assertNotIn(secret, sent)
            self.assertNotIn(json.dumps(secret)[1:-1], sent)
        event = json.loads(sent)
        value = event["exception"]["values"][0]
        self.assertEqual(value["type"], "RuntimeError")
        self.assertNotIn("'findings'", value["value"])  # quoted text goes whole
        self.assertEqual(value["stacktrace"]["frames"][-1]["function"], "scan_error")
        self.assertEqual(event["transaction"], "POST /api/scan-url")
        self.assertEqual(event["tags"], {"app": "psychosecurity", "where": "request"})
        self.assertNotIn("request", event)

    def test_the_route_is_the_function_never_the_address_asked_for(self):
        self.assertEqual(self.site.route("GET", "/api/scan"), "GET /api/scan")
        self.assertEqual(self.site.route("GET", "/badge/acme-corp.svg"), "GET /api/badge")
        self.assertEqual(self.site.route("GET", "/acme-corp/payroll-internal"), "")
        self.assertEqual(self.site.route("G T", "/api/scan"), "")

    def test_a_crash_without_a_dsn_sends_nothing(self):
        with mock.patch.dict(os.environ, {}, clear=False), mock.patch("urllib.request.urlopen") as urlopen, \
                mock.patch("traceback.print_exc") as printed, self.crash():
            os.environ.pop("SENTRY_DSN", None)
            status, _ = call(self.site, "/api/scan-url")
        self.assertTrue(status.startswith("500"))
        printed.assert_called_once()        # the container log still has it
        urlopen.assert_not_called()

    def test_a_page_that_is_not_there_is_not_reported(self):
        with mock.patch.dict(os.environ, self.DSN), mock.patch.object(server, "report_crash") as report:
            status, _ = call(self.site, "/nothing-here")
        self.assertTrue(status.startswith("404"))
        report.assert_not_called()

    def test_a_failing_tracker_never_breaks_the_answer(self):
        with mock.patch.dict(os.environ, self.DSN), mock.patch("traceback.print_exc"), \
                mock.patch.object(errorreport, "capture_exception", side_effect=OSError("down")), self.crash():
            status, _ = call(self.site, "/api/scan-url")
        self.assertTrue(status.startswith("500"))


if __name__ == "__main__":
    unittest.main()
