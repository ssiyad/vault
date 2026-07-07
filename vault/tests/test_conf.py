import unittest
from unittest.mock import patch

from vault.conf import VaultConf


def fake_get_secret(key: str, ttl: int = 60) -> str:
	if key == "explode":
		raise RuntimeError("vault unreachable")
	return f"SECRET::{key}"


class TestVaultConf(unittest.TestCase):
	def setUp(self):
		self.p = patch("vault.client.get_secret", fake_get_secret)
		self.p.start()
		self.conf = VaultConf(
			{
				"mailgun_api_key": "vault/siteA/mailgun_api_key",
				"db_host": "10.0.0.5",
			}
		)

	def tearDown(self):
		self.p.stop()

	def test_prefixed_value_resolves_and_strips(self):
		self.assertEqual(self.conf.get("mailgun_api_key"), "SECRET::siteA/mailgun_api_key")

	def test_plain_value_untouched(self):
		self.assertEqual(self.conf.get("db_host"), "10.0.0.5")

	def test_missing_key_returns_default(self):
		self.assertIsNone(self.conf.get("nope"))
		self.assertEqual(self.conf.get("nope", "fallback"), "fallback")

	def test_getitem_resolves(self):
		self.assertEqual(self.conf["mailgun_api_key"], "SECRET::siteA/mailgun_api_key")

	def test_getitem_missing_raises_keyerror(self):
		with self.assertRaises(KeyError):
			self.conf["nope"]

	def test_attribute_access_resolves(self):
		self.assertEqual(self.conf.mailgun_api_key, "SECRET::siteA/mailgun_api_key")
		self.assertEqual(self.conf.db_host, "10.0.0.5")

	def test_attribute_access_missing_is_none(self):
		self.assertIsNone(self.conf.nope)

	def test_copy_stays_vaultconf_and_resolves(self):
		clone = self.conf.copy()
		self.assertIsInstance(clone, VaultConf)
		self.assertEqual(clone.get("mailgun_api_key"), "SECRET::siteA/mailgun_api_key")

	def test_fail_closed_propagates(self):
		conf = VaultConf({"broken": "vault/explode"})
		with self.assertRaises(RuntimeError):
			conf.get("broken")


if __name__ == "__main__":
	unittest.main()
