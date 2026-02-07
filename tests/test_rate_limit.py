import unittest

from ghostmcp.rate_limit import SlidingWindowRateLimiter


class RateLimitTests(unittest.TestCase):
    def test_allows_within_budget(self) -> None:
        limiter = SlidingWindowRateLimiter(max_calls=2, window_seconds=60)
        self.assertTrue(limiter.allow())
        self.assertTrue(limiter.allow())
        self.assertFalse(limiter.allow())


if __name__ == "__main__":
    unittest.main()
