"""Signed badges (plan §0.6): the signature, the claims, the levels, expiry,
provenance, the combined badge and the endpoints. No network."""

from __future__ import annotations

import datetime as dt
import importlib.util
import io
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vis_fakes import NOW, healthy_site  # noqa: E402

from vibecheck.checks.security import CHECK as SECURITY  # noqa: E402
from vibecheck.checks.visibility import CHECK as VISIBILITY  # noqa: E402
from vibecheck.core import badge, ed25519, signing  # noqa: E402
from vibecheck.core.models import Context, Target  # noqa: E402
from vibecheck.core.signed import with_signatures  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SEED = bytes(range(32))
SIGNER = signing.Signer(SEED)
KEYS = signing.public_keys(env={}, signer=SIGNER)
LATER = NOW + dt.timedelta(days=10)


def load_api(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "api" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def results(site=None):
    ctx = Context(fetch_override=(site or healthy_site()).fetch, now=NOW)
    return (SECURITY.run(Target(url="https://groomly.test"), ctx),
            VISIBILITY.run(Target(url="https://groomly.test"), ctx))


class Ed25519Test(unittest.TestCase):
    # RFC 8032 §7.1, tests 1 to 3.
    VECTORS = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    def test_rfc_8032_vectors(self):
        for sk, pk, msg, sig in self.VECTORS:
            sk, pk, msg, sig = map(bytes.fromhex, (sk, pk, msg, sig))
            with self.subTest(pk.hex()[:8]):
                self.assertEqual(ed25519.public_key(sk), pk)
                self.assertEqual(ed25519.sign(sk, msg), sig)
                self.assertTrue(ed25519.verify(pk, msg, sig))
                self.assertFalse(ed25519.verify(pk, msg + b"!", sig))

    def test_rejects_malformed_and_malleable_signatures(self):
        pk = ed25519.public_key(SEED)
        sig = ed25519.sign(SEED, b"m")
        s_plus_l = (int.from_bytes(sig[32:], "little") + (2 ** 252 + 27742317777372353535851937790883648493))
        self.assertFalse(ed25519.verify(pk, b"m", sig[:32] + s_plus_l.to_bytes(32, "little")))
        self.assertFalse(ed25519.verify(pk, b"m", sig[:63]))
        self.assertFalse(ed25519.verify(b"\xff" * 32, b"m", sig))

    def test_same_signatures_as_the_audited_library(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("cryptography not installed")
        for i in range(5):
            seed, msg = os.urandom(32), os.urandom(50 + i)
            self.assertEqual(Ed25519PrivateKey.from_private_bytes(seed).sign(msg), ed25519.sign(seed, msg))


class SigningTest(unittest.TestCase):
    def test_key_from_the_environment(self):
        env = {"VIBECHECK_SIGNING_KEY": signing.b64url(SEED),
               "VIBECHECK_OLD_PUBLIC_KEYS": signing.b64url(ed25519.public_key(b"\x01" * 32))}
        signer = signing.load_signer(env)
        self.assertEqual(signer.kid, SIGNER.kid)
        keys = signing.public_keys(env)
        self.assertEqual([k["status"] for k in keys], ["current", "retired"])
        self.assertIsNone(signing.load_signer({}))
        with self.assertRaises(ValueError):
            signing.load_signer({"VIBECHECK_SIGNING_KEY": "short"})

    def test_envelope_statuses(self):
        env = SIGNER.envelope(signing.REPORT, {"a": 1, "b": [1, 2]})
        self.assertEqual(env["p"], '{"a":1,"b":[1,2]}')
        self.assertEqual(signing.verify_envelope(env, signing.REPORT, KEYS), signing.VERIFIED)
        self.assertEqual(signing.verify_envelope(dict(env, p='{"a":2,"b":[1,2]}'), signing.REPORT, KEYS),
                         signing.TAMPERED)
        self.assertEqual(signing.verify_envelope(env, signing.BADGE, KEYS), signing.TAMPERED,
                         "a report signature must not pass as a badge")
        self.assertEqual(signing.verify_envelope(dict(env, kid="nope"), signing.REPORT, KEYS), signing.UNKNOWN_KEY)
        self.assertEqual(signing.verify_envelope(signing.unsigned_envelope({"a": 1}), signing.REPORT, KEYS),
                         signing.UNSIGNED)
        for junk in ({}, {"p": 5}, {"p": "x", "sig": "!!!", "kid": SIGNER.kid}):
            self.assertEqual(signing.verify_envelope(junk, signing.REPORT, KEYS), signing.TAMPERED)

    def test_retired_keys_still_verify(self):
        old = signing.Signer(b"\x02" * 32)
        env = old.envelope(signing.REPORT, {"x": 1})
        keys = signing.public_keys(env={"VIBECHECK_OLD_PUBLIC_KEYS": signing.b64url(old.public)}, signer=SIGNER)
        self.assertEqual(signing.verify_envelope(env, signing.REPORT, keys), signing.VERIFIED)


class ClaimTest(unittest.TestCase):
    def test_report_claim_pins_target_time_and_findings(self):
        _sec, vis = results()
        claim = badge.report_claim(vis, badge.provenance("server"))
        self.assertEqual(claim["target"], {"url": "https://groomly.test"})
        self.assertEqual(claim["scanned_at"], "2026-10-27T12:00:00Z")
        self.assertEqual(claim["expires_at"], "2026-11-26T12:00:00Z")
        self.assertEqual(claim["level"], "gold")
        self.assertEqual(len(claim["findings"]), len(vis.findings))

    def test_badge_names_its_report(self):
        sec, _vis = results()
        signed = badge.sign_result(sec, SIGNER, badge.provenance("server"))
        claim = json.loads(signed["badge"]["p"])
        self.assertEqual(claim["report"], signing.digest(signed["report"]["p"]))
        self.assertNotIn("findings", claim, "the badge stays small; the report carries the findings")

    def test_security_pins_the_url_it_ended_up_at(self):
        site = healthy_site()
        site.add("https://www.groomly.test/", site.responses["https://www.groomly.test/"])
        result = SECURITY.run(Target(url="https://www.groomly.test"), Context(fetch_override=site.fetch, now=NOW))
        self.assertEqual(result.target.url, "https://groomly.test")

    def test_provenance(self):
        self.assertEqual(badge.provenance("ci", "https://github.com/a/b/actions/runs/123"),
                         {"by": "ci", "run": "https://github.com/a/b/actions/runs/123"})
        self.assertEqual(badge.provenance("ci", "https://evil.test/runs/1"), {"by": "self"})
        env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "a/b", "GITHUB_RUN_ID": "9"}
        self.assertEqual(badge.ci_provenance(env)["run"], "https://github.com/a/b/actions/runs/9")
        self.assertEqual(badge.ci_provenance({}), {"by": "self"})

    def test_links_round_trip(self):
        sec, vis = results()
        envs = [badge.sign_result(r, SIGNER, badge.provenance("server"))["report"] for r in (sec, vis)]
        self.assertEqual(badge.decode_report_link(badge.encode_report_link(envs)), envs)
        b = badge.sign_result(vis, SIGNER, badge.provenance("server"))["badge"]
        self.assertEqual(badge.decode_badge_param(badge.encode_badge_param(b)), b)


class BadgeImageTest(unittest.TestCase):
    def view(self, result, prov=None, signer=SIGNER, now=LATER, check=None):
        env = badge.sign_result(result, signer, prov or badge.provenance("server"))["badge"]
        return badge.badge_view(check or result.check_id, env, KEYS, now)

    def test_verified_badge_shows_level_and_date(self):
        _sec, vis = results()
        label, value, color = self.view(vis)
        self.assertEqual(label, "vibecheck visibility")
        self.assertEqual(value, "gold · 27 Oct 2026")
        self.assertEqual(color, badge.COLORS["gold"])

    def test_goes_grey_after_thirty_days(self):
        _sec, vis = results()
        self.assertEqual(self.view(vis, now=NOW + dt.timedelta(days=30))[1], "expired · rescan")
        self.assertEqual(self.view(vis, now=NOW + dt.timedelta(days=29, hours=23))[1], "gold · 27 Oct 2026")

    def test_self_reported_and_ci(self):
        _sec, vis = results()
        self.assertTrue(self.view(vis, badge.provenance("self"), signer=None)[1].endswith("self-reported"))
        ci = badge.provenance("ci", "https://github.com/a/b/actions/runs/1")
        self.assertTrue(self.view(vis, ci, signer=None)[1].endswith("CI run"))

    def test_a_self_reported_claim_cannot_pass_as_ours(self):
        # Unsigned but claiming our server ran it: still not verified.
        _sec, vis = results()
        self.assertTrue(self.view(vis, badge.provenance("server"), signer=None)[1].endswith("unsigned"))

    def test_tampering_and_mismatches_are_unverified(self):
        sec, vis = results()
        env = badge.sign_result(vis, SIGNER, badge.provenance("server"))["badge"]
        forged = dict(env, p=env["p"].replace('"level":"gold"', '"level":"gold","x":1'))
        self.assertEqual(badge.badge_view("visibility", forged, KEYS, LATER)[1], "unverified")
        self.assertEqual(badge.badge_view("security", env, KEYS, LATER)[1], "unverified",
                         "a visibility badge can't be shown as a security one")
        self.assertIn("unverified", badge.render("visibility", "not-base64!", KEYS, LATER))

    def test_repo_badges_say_which_commit(self):
        result = SECURITY.run(Target(repo=str(ROOT / "vibecheck" / "checks" / "security" / "fixtures" / "sample-app"),
                                     commit="abc1234def5678"), Context(now=NOW))
        _label, value, _c = self.view(result, badge.provenance("self"), signer=None)
        self.assertIn("commit abc1234", value)

    def test_nothing_from_the_url_reaches_the_svg(self):
        evil = signing.unsigned_envelope({"check": "visibility", "level": "<script>alert(1)</script>",
                                          "total": "<b>", "scanned_at": "2026-10-27T12:00:00Z",
                                          "expires_at": "2026-11-26T12:00:00Z",
                                          "target": {"commit": "</text><script>"}, "provenance": {"by": "self"}})
        svg = badge.render("visibility", badge.encode_badge_param(evil), KEYS, LATER)
        self.assertNotIn("<script", svg)
        self.assertNotIn("<b>", svg)
        self.assertIn("no level", svg)
        self.assertIn("vibecheck", badge.render("<svg onload=x>", None, KEYS, LATER))
        self.assertNotIn("onload", badge.render("<svg onload=x>", None, KEYS, LATER))


class CombinedTest(unittest.TestCase):
    REQUIRED = ["security", "visibility"]

    def envs(self, site=None, signer=SIGNER):
        return [badge.sign_result(r, signer, badge.provenance("server"))["report"] for r in results(site)]

    def test_issued_when_every_check_passes(self):
        claim, reason = badge.combined_claim(self.envs(), KEYS, LATER, self.REQUIRED)
        self.assertEqual(reason, "")
        self.assertEqual(claim["check"], "vibechecked")
        self.assertEqual(set(claim["checks"]), {"security", "visibility"})
        self.assertIn(claim["level"], badge.LEVEL_ORDER)

    def test_refusals(self):
        envs = self.envs()
        cases = {
            "unsigned": [signing.unsigned_envelope(json.loads(e["p"])) for e in envs],
            "missing": envs[:1],
            "expired": envs,
        }
        self.assertIn("signed by psychosecurity.io", badge.combined_claim(cases["unsigned"], KEYS, LATER, self.REQUIRED)[1])
        self.assertIn("missing visibility", badge.combined_claim(cases["missing"], KEYS, LATER, self.REQUIRED)[1])
        self.assertIn("30 days", badge.combined_claim(envs, KEYS, NOW + dt.timedelta(days=31), self.REQUIRED)[1])

        # Same two checks, but one was run on a different site.
        moved = json.loads(envs[1]["p"])
        moved["target"] = {"url": "https://other.test"}
        mixed = [envs[0], SIGNER.envelope(signing.REPORT, moved)]
        self.assertIn("different targets", badge.combined_claim(mixed, KEYS, LATER, self.REQUIRED)[1])

        # www and bare are the same site.
        www = json.loads(envs[1]["p"])
        www["target"] = {"url": "https://www.groomly.test"}
        same = [envs[0], SIGNER.envelope(signing.REPORT, www)]
        self.assertEqual(badge.combined_claim(same, KEYS, LATER, self.REQUIRED)[1], "")

    def test_needs_bronze_everywhere(self):
        site = healthy_site()
        # A readable .env is critical: no level for security, so no combined badge.
        from vibecheck.urlscan import Response
        site.add("https://groomly.test/.env", Response(200, {"content-type": "text/plain"},
                                                       "SECRET_KEY=abc\n", "https://groomly.test/.env"))
        envs = self.envs(site)
        self.assertIsNone(json.loads(envs[0]["p"])["level"])
        claim, reason = badge.combined_claim(envs, KEYS, LATER, self.REQUIRED)
        self.assertIsNone(claim)
        self.assertIn("bronze or above; not yet: security", reason)


class EndpointTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"VIBECHECK_SIGNING_KEY": signing.b64url(SEED),
                                               "VIBECHECK_RATE_LIMIT_OFF": "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def serve(self, filename):
        module = load_api(filename.replace(".", "_"), filename)
        server = ThreadingHTTPServer(("127.0.0.1", 0), module.handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def request(self, url, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"},
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_public_key_is_published(self):
        status, headers, body = self.request(self.serve("key.py") + "/api/key")
        keys = json.loads(body)["keys"]
        self.assertEqual(keys[0]["kid"], SIGNER.kid)
        self.assertEqual(keys[0]["x"], signing.b64url(SIGNER.public))

    def test_hosted_results_are_signed(self):
        payload = with_signatures(results()[1])
        self.assertEqual(signing.verify_envelope(payload["signed"]["report"], signing.REPORT, KEYS), signing.VERIFIED)
        self.assertEqual(signing.verify_envelope(payload["signed"]["badge"], signing.BADGE, KEYS), signing.VERIFIED)
        self.assertEqual(payload["level"], "gold")

    def test_badge_endpoint(self):
        base = self.serve("badge.py")
        env = with_signatures(results()[1])["signed"]["badge"]
        status, headers, body = self.request(f"{base}/api/badge?check=visibility&r={badge.encode_badge_param(env)}")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "image/svg+xml; charset=utf-8")
        self.assertIn(b"gold", body)
        # The old score badge still works for existing READMEs.
        self.assertIn(b"94/100 A", self.request(f"{base}/api/badge?score=94")[2])

    def test_verify_endpoint(self):
        base = self.serve("verify.py")
        env = with_signatures(results()[1])["signed"]["report"]
        ok = json.loads(self.request(base + "/api/verify", {"envelope": env, "kind": "report"})[2])
        bad = json.loads(self.request(base + "/api/verify", {"envelope": dict(env, p=env["p"] + " "), "kind": "report"})[2])
        self.assertEqual((ok["status"], bad["status"]), ("verified", "tampered"))
        self.assertEqual(self.request(base + "/api/verify", {"kind": "report"})[0], 400)

    def test_vibechecked_endpoint(self):
        base = self.serve("vibechecked.py")
        reports = [with_signatures(r)["signed"]["report"] for r in results()]
        status, _h, body = self.request(base + "/api/vibechecked", {"reports": reports})
        data = json.loads(body)
        self.assertEqual(status, 200, data)
        self.assertIn("/badge/vibechecked.svg?r=", data["markdown"])
        self.assertEqual(signing.verify_envelope(data["badge"], signing.BADGE, KEYS), signing.VERIFIED)
        status, _h, body = self.request(base + "/api/vibechecked", {"reports": reports[:1]})
        self.assertEqual(status, 400)
        self.assertIn("missing visibility", json.loads(body)["error"])

    def test_upload_reports_are_signed_but_get_no_badge(self):
        legacy = SECURITY.run(Target(files=[("a.py", "x = 1\n")]), Context(now=NOW))
        payload = with_signatures(legacy, sign_badge=False)
        self.assertIn("report", payload["signed"])
        self.assertNotIn("badge", payload["signed"])


class CliBadgeTest(unittest.TestCase):
    def run_cli(self, *argv, env=None):
        from vibecheck import cli
        from vibecheck.core import fetcher
        out = io.StringIO()
        with mock.patch.object(fetcher, "build_fetcher", return_value=healthy_site().fetch), \
                mock.patch.dict(os.environ, env or {}, clear=False), redirect_stdout(out):
            cli.main(list(argv))
        return out.getvalue()

    def badge_claim(self, out):
        line = [ln for ln in out.splitlines() if "/badge/visibility.svg" in ln][0]
        param = line.split("svg?r=", 1)[1].split(")", 1)[0]
        return json.loads(badge.decode_badge_param(param)["p"])

    def test_self_reported_from_a_laptop(self):
        out = self.run_cli("https://groomly.test", "--checks", "visibility", "--badge", "--no-color",
                           env={"GITHUB_ACTIONS": ""})
        claim = self.badge_claim(out)
        self.assertEqual(claim["provenance"], {"by": "self"})
        self.assertIn("/report#r=", out)

    def test_ci_run_from_github_actions(self):
        out = self.run_cli("https://groomly.test", "--checks", "visibility", "--badge", "--no-color",
                           env={"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "a/b", "GITHUB_RUN_ID": "77"})
        self.assertEqual(self.badge_claim(out)["provenance"],
                         {"by": "ci", "run": "https://github.com/a/b/actions/runs/77"})


if __name__ == "__main__":
    unittest.main()
