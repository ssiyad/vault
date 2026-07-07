import unittest

from vault.policy import _ip_allowed, _pattern_matches


class TestPatternMatching(unittest.TestCase):
	def test_exact_match(self):
		self.assertTrue(_pattern_matches("site-a/stripe_key", "site-a/stripe_key"))
		self.assertFalse(_pattern_matches("site-a/stripe_key", "site-a/stripe_key2"))

	def test_prefix_match(self):
		self.assertTrue(_pattern_matches("site-a/*", "site-a/stripe_key"))
		self.assertTrue(_pattern_matches("site-a/*", "site-a/nested/key"))
		self.assertFalse(_pattern_matches("site-a/*", "site-b/stripe_key"))

	def test_star_alone_matches_everything(self):
		self.assertTrue(_pattern_matches("*", "anything/at/all"))

	def test_empty_pattern_never_matches(self):
		self.assertFalse(_pattern_matches("", "site-a/key"))
		self.assertFalse(_pattern_matches(None, "site-a/key"))
		self.assertFalse(_pattern_matches("  ", "site-a/key"))


class TestIpAllowlist(unittest.TestCase):
	def test_empty_allowlist_allows_all(self):
		self.assertTrue(_ip_allowed(None, "10.0.0.1"))
		self.assertTrue(_ip_allowed("", "10.0.0.1"))

	def test_allowlist_filters(self):
		self.assertTrue(_ip_allowed("10.0.0.1, 10.0.0.2", "10.0.0.2"))
		self.assertFalse(_ip_allowed("10.0.0.1, 10.0.0.2", "10.0.0.3"))
		self.assertFalse(_ip_allowed("10.0.0.1", None))


if __name__ == "__main__":
	unittest.main()
