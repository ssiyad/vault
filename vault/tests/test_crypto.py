import base64
import json
import os
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from vault.crypto import (
	KEK_CURRENT_ENV,
	KEKS_ENV,
	VaultKeyError,
	decrypt_secret,
	encrypt_secret,
	load_keks,
	rewrap_dek,
)


def make_env(versions: dict[str, bytes], current: str) -> dict[str, str]:
	return {
		KEKS_ENV: json.dumps({v: base64.b64encode(k).decode() for v, k in versions.items()}),
		KEK_CURRENT_ENV: current,
	}


KEK_V1 = os.urandom(32)
KEK_V2 = os.urandom(32)
ENV_V1 = make_env({"v1": KEK_V1}, "v1")
ENV_V1_V2 = make_env({"v1": KEK_V1, "v2": KEK_V2}, "v2")


class TestKekLoading(unittest.TestCase):
	def test_missing_env_raises(self):
		with patch.dict(os.environ, {}, clear=True), self.assertRaises(VaultKeyError):
			load_keks()

	def test_current_without_entry_raises(self):
		env = make_env({"v1": KEK_V1}, "v9")
		with patch.dict(os.environ, env), self.assertRaises(VaultKeyError):
			load_keks()

	def test_malformed_json_raises(self):
		env = {KEKS_ENV: "not-json", KEK_CURRENT_ENV: "v1"}
		with patch.dict(os.environ, env), self.assertRaises(VaultKeyError):
			load_keks()

	def test_wrong_key_length_raises(self):
		env = make_env({"v1": os.urandom(16)}, "v1")
		with patch.dict(os.environ, env), self.assertRaises(VaultKeyError):
			load_keks()

	def test_loads_versions_and_current(self):
		with patch.dict(os.environ, ENV_V1_V2):
			keks, current = load_keks()
		self.assertEqual(current, "v2")
		self.assertEqual(keks, {"v1": KEK_V1, "v2": KEK_V2})


class TestEnvelope(unittest.TestCase):
	def test_round_trip(self):
		value = "sk_live_abc123 <b>&é</b>".encode()
		with patch.dict(os.environ, ENV_V1):
			row = encrypt_secret(value)
			self.assertEqual(decrypt_secret(row), value)
		self.assertEqual(row.kek_version, "v1")
		# stored fields are base64 text, plaintext never among them
		for field in (row.ciphertext, row.value_nonce, row.wrapped_dek, row.dek_nonce):
			self.assertNotIn(value, base64.b64decode(field))

	def test_unique_deks_and_nonces(self):
		with patch.dict(os.environ, ENV_V1):
			a = encrypt_secret(b"same value")
			b = encrypt_secret(b"same value")
		self.assertNotEqual(a.ciphertext, b.ciphertext)
		self.assertNotEqual(a.wrapped_dek, b.wrapped_dek)
		self.assertNotEqual(a.value_nonce, b.value_nonce)

	def test_wrong_kek_fails_loudly(self):
		with patch.dict(os.environ, ENV_V1):
			row = encrypt_secret(b"topsecret")
		wrong = make_env({"v1": os.urandom(32)}, "v1")
		with patch.dict(os.environ, wrong), self.assertRaises(InvalidTag):
			decrypt_secret(row)

	def test_missing_kek_version_raises(self):
		with patch.dict(os.environ, ENV_V1):
			row = encrypt_secret(b"topsecret")
		only_v2 = make_env({"v2": KEK_V2}, "v2")
		with patch.dict(os.environ, only_v2), self.assertRaises(VaultKeyError):
			decrypt_secret(row)

	def test_tampered_ciphertext_fails_loudly(self):
		with patch.dict(os.environ, ENV_V1):
			row = encrypt_secret(b"topsecret")
			raw = bytearray(base64.b64decode(row.ciphertext))
			raw[0] ^= 0xFF
			row.ciphertext = base64.b64encode(bytes(raw)).decode()
			with self.assertRaises(InvalidTag):
				decrypt_secret(row)


class TestRotation(unittest.TestCase):
	def test_rewrap_preserves_value_and_ciphertext(self):
		with patch.dict(os.environ, make_env({"v1": KEK_V1}, "v1")):
			row = encrypt_secret(b"rotate me")

		with patch.dict(os.environ, ENV_V1_V2):
			before = (row.ciphertext, row.value_nonce, row.wrapped_dek)
			rewrap_dek(row, "v2")
			self.assertEqual(row.kek_version, "v2")
			self.assertEqual(row.ciphertext, before[0])  # value bytes never move
			self.assertEqual(row.value_nonce, before[1])
			self.assertNotEqual(row.wrapped_dek, before[2])
			self.assertEqual(decrypt_secret(row), b"rotate me")

		# old KEK can be dropped once nothing references it
		only_v2 = make_env({"v2": KEK_V2}, "v2")
		with patch.dict(os.environ, only_v2):
			self.assertEqual(decrypt_secret(row), b"rotate me")

	def test_rewrap_to_unknown_version_raises(self):
		with patch.dict(os.environ, ENV_V1):
			row = encrypt_secret(b"x")
			with self.assertRaises(VaultKeyError):
				rewrap_dek(row, "v9")


if __name__ == "__main__":
	unittest.main()
