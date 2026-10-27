"""Record a live visibility crawl as a test fixture, and snapshot its report.

    python3 scripts/record_visibility_fixture.py robinofloxley.com --name robinofloxley

writes tests/fixtures/<name>.json.gz (every response the crawl saw) and
tests/fixtures/<name>.expected.json (the report those responses produce).
tests/test_visibility_fixture.py replays the first and compares against the
second, so any change to a check shows up as a diff in review.

Re-snapshot without re-crawling (after deliberately changing a check):

    python3 scripts/record_visibility_fixture.py --name robinofloxley --replay
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vibecheck.visibility import scan_visibility  # noqa: E402
from vibecheck.visibility.fetch import Fetched, build_fetcher  # noqa: E402
from vibecheck.visibility.report import render_json  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
KEEP_HEADERS = ("content-type", "content-length", "location", "last-modified")
IMAGE_BODY_BYTES = 65536  # enough to read any image header


def record(url: str):
    live = build_fetcher(guard=False)
    responses = {}

    def fetch(target, method="GET"):
        resp = live(target, method)
        key = f"{method} {target}"
        if resp is None:
            responses[key] = None
            return None
        body = resp.body
        if resp.content_type.startswith("image/"):
            body = body[:IMAGE_BODY_BYTES]
        responses[key] = {
            "url": resp.url, "status": resp.status, "chain": resp.chain,
            "headers": {k: v for k, v in resp.headers.items() if k in KEEP_HEADERS},
            "body": base64.b64encode(body).decode("ascii"),
        }
        return resp

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    result = scan_visibility(url, fetch, now=now)
    return {"url": url, "now": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "responses": responses}, result


class Replay:
    """A fetcher over recorded responses. Anything not recorded is a failed
    request, which is what an offline replay should see."""

    def __init__(self, fixture: dict):
        self.responses = fixture["responses"]
        self.misses = []

    def fetch(self, target, method="GET"):
        key = f"{method} {target}"
        if key not in self.responses:
            self.misses.append(key)
            return None
        r = self.responses[key]
        if r is None:
            return None
        return Fetched(url=r["url"], status=r["status"], headers=dict(r["headers"]),
                       body=base64.b64decode(r["body"]), chain=[tuple(h) for h in r["chain"]])


def load_fixture(name: str) -> dict:
    with gzip.open(FIXTURES / f"{name}.json.gz", "rt", encoding="utf-8") as fh:
        return json.load(fh)


def replay(fixture: dict):
    now = dt.datetime.strptime(fixture["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    return scan_visibility(fixture["url"], Replay(fixture).fetch, now=now)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("url", nargs="?")
    parser.add_argument("--name", required=True)
    parser.add_argument("--replay", action="store_true", help="re-snapshot from the recorded fixture")
    args = parser.parse_args(argv)

    FIXTURES.mkdir(parents=True, exist_ok=True)
    if args.replay:
        fixture = load_fixture(args.name)
        result = replay(fixture)
    else:
        if not args.url:
            parser.error("a URL is needed unless --replay")
        fixture, _live = record(args.url)
        with gzip.open(FIXTURES / f"{args.name}.json.gz", "wt", encoding="utf-8") as fh:
            json.dump(fixture, fh, sort_keys=True)
        # Snapshot from the replay, not the live run, so the snapshot is
        # exactly what the test will reproduce.
        result = replay(fixture)
    (FIXTURES / f"{args.name}.expected.json").write_text(render_json(result), encoding="utf-8")
    print(f"{args.name}: {len(fixture['responses'])} responses, score {result.score}, "
          f"{len(result.findings)} findings, {len(result.passes)} passes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
