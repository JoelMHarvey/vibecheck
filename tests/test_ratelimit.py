"""Tests for the hosted API's rate limiting.

The clock is injected so window rollover is tested deterministically, and
the KV backend's HTTP call is injected so nothing touches the network.
"""

import unittest

from vibecheck.ratelimit import (
    Decision,
    KVBackend,
    MemoryBackend,
    RateLimiter,
    client_ip,
)


class FakeClock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class RateLimiterTest(unittest.TestCase):
    def test_allows_up_to_limit_then_blocks(self):
        clock = FakeClock()
        limiter = RateLimiter("t", [(3, 60)], backend=MemoryBackend(), clock=clock)
        for i in range(3):
            self.assertTrue(limiter.check("1.2.3.4").allowed, f"request {i + 1} should pass")
        self.assertFalse(limiter.check("1.2.3.4").allowed)

    def test_window_rollover_restores_quota(self):
        clock = FakeClock()
        limiter = RateLimiter("t", [(2, 60)], backend=MemoryBackend(), clock=clock)
        limiter.check("ip"); limiter.check("ip")
        self.assertFalse(limiter.check("ip").allowed)
        clock.advance(61)
        self.assertTrue(limiter.check("ip").allowed)

    def test_identities_are_independent(self):
        limiter = RateLimiter("t", [(1, 60)], backend=MemoryBackend(), clock=FakeClock())
        self.assertTrue(limiter.check("a").allowed)
        self.assertFalse(limiter.check("a").allowed)
        self.assertTrue(limiter.check("b").allowed, "one IP must not consume another's quota")

    def test_limiters_do_not_share_namespace(self):
        backend = MemoryBackend()
        clock = FakeClock()
        one = RateLimiter("scan", [(1, 60)], backend=backend, clock=clock)
        two = RateLimiter("scanurl", [(1, 60)], backend=backend, clock=clock)
        self.assertTrue(one.check("ip").allowed)
        self.assertTrue(two.check("ip").allowed, "endpoints must have separate budgets")

    def test_retry_after_is_time_until_window_reset(self):
        clock = FakeClock(now=1000.0)   # 1000 // 60 = bucket 16, resets at 1020
        limiter = RateLimiter("t", [(1, 60)], backend=MemoryBackend(), clock=clock)
        limiter.check("ip")
        decision = limiter.check("ip")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.retry_after, 20)

    def test_tightest_window_reported_first(self):
        """With 2/min and 100/hour, the minute limit should be the one that
        trips — and the hint should be seconds, not an hour."""
        clock = FakeClock()
        limiter = RateLimiter("t", [(100, 3600), (2, 60)], backend=MemoryBackend(), clock=clock)
        limiter.check("ip"); limiter.check("ip")
        decision = limiter.check("ip")
        self.assertEqual(decision.window, 60)
        self.assertLessEqual(decision.retry_after, 60)

    def test_hourly_window_still_enforced_across_minutes(self):
        clock = FakeClock()
        limiter = RateLimiter("t", [(5, 3600), (3, 60)], backend=MemoryBackend(), clock=clock)
        allowed = 0
        for _ in range(10):          # spread over 10 minutes: minute limit never trips
            if limiter.check("ip").allowed:
                allowed += 1
            clock.advance(60)
        self.assertEqual(allowed, 5, "hourly cap should bound the total")

    def test_failing_backend_fails_open(self):
        class Broken:
            def incr(self, key, window):
                raise RuntimeError("kv down")

        limiter = RateLimiter("t", [(1, 60)], backend=Broken(), clock=FakeClock())
        self.assertTrue(limiter.check("ip").allowed, "a broken limiter must not break the API")

    def test_message_mentions_cli_escape_hatch(self):
        limiter = RateLimiter("t", [(1, 60)], backend=MemoryBackend(), clock=FakeClock())
        limiter.check("ip")
        self.assertIn("CLI", limiter.check("ip").message)

    def test_memory_backend_is_bounded(self):
        backend = MemoryBackend(max_keys=50)
        for i in range(500):
            backend.incr(f"key-{i}", 60)
        self.assertLessEqual(len(backend._counts), 50)

    def test_requires_at_least_one_window(self):
        with self.assertRaises(ValueError):
            RateLimiter("t", [])


class KVBackendTest(unittest.TestCase):
    def test_pipelines_incr_and_expire(self):
        seen = {}

        def fake_post(url, headers, commands):
            seen["url"] = url
            seen["headers"] = headers
            seen["commands"] = commands
            return [{"result": 7}, {"result": 1}]

        backend = KVBackend("https://kv.example", "tok3n", post=fake_post)
        self.assertEqual(backend.incr("rl:x", 60), 7)
        self.assertEqual(seen["url"], "https://kv.example/pipeline")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer tok3n")
        self.assertEqual(seen["commands"][0], ["INCR", "rl:x"])
        # EXPIRE ... NX so later hits can't extend the window.
        self.assertEqual(seen["commands"][1], ["EXPIRE", "rl:x", "60", "NX"])

    def test_limiter_uses_kv_counts(self):
        counts = {"n": 0}

        def fake_post(url, headers, commands):
            counts["n"] += 1
            return [{"result": counts["n"]}, {"result": 1}]

        limiter = RateLimiter("t", [(2, 60)], backend=KVBackend("https://k", "t", post=fake_post),
                              clock=FakeClock())
        self.assertTrue(limiter.check("ip").allowed)
        self.assertTrue(limiter.check("ip").allowed)
        self.assertFalse(limiter.check("ip").allowed)


class ClientIpTest(unittest.TestCase):
    def test_prefers_platform_header(self):
        self.assertEqual(client_ip({"x-real-ip": "9.9.9.9", "x-forwarded-for": "1.1.1.1"}), "9.9.9.9")

    def test_spoofed_forwarded_for_does_not_win(self):
        """A client can prepend its own XFF entry; proxies append the real
        one, so the LAST value is the trustworthy one."""
        headers = {"x-forwarded-for": "6.6.6.6, 203.0.113.7"}
        self.assertEqual(client_ip(headers), "203.0.113.7")

    def test_falls_back_when_no_headers(self):
        self.assertEqual(client_ip({}), "unknown")

    def test_ignores_blank_entries(self):
        self.assertEqual(client_ip({"x-forwarded-for": "1.1.1.1, ,  "}), "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
