"""Envelope encryption core: AES-256-GCM with versioned master keys (KEKs).

Every secret value is encrypted with its own random 32-byte data key (DEK);
the DEK is wrapped with the current KEK version. KEKs live only in the
environment of the vault host (VAULT_KEKS / VAULT_KEK_CURRENT) and never
touch the database. Rotation re-wraps DEKs without touching ciphertext.

This module is deliberately frappe-free so it can be tested standalone.
"""

import base64
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEKS_ENV = "VAULT_KEKS"
KEK_CURRENT_ENV = "VAULT_KEK_CURRENT"

DEK_BYTES = 32
NONCE_BYTES = 12


class VaultKeyError(Exception):
	"""KEK configuration is missing or malformed. Crypto refuses to run."""


def load_keks() -> tuple[dict[str, bytes], str]:
	"""Return (version -> 32-byte KEK, current version) strictly from the environment."""
	raw = os.environ.get(KEKS_ENV)
	current = os.environ.get(KEK_CURRENT_ENV)
	if not raw or not current:
		raise VaultKeyError(
			f"{KEKS_ENV} and {KEK_CURRENT_ENV} must be set in the vault host environment"
		)

	try:
		parsed = json.loads(raw)
	except json.JSONDecodeError as e:
		raise VaultKeyError(f"{KEKS_ENV} is not valid JSON") from e

	if not isinstance(parsed, dict) or not parsed:
		raise VaultKeyError(f"{KEKS_ENV} must be a non-empty JSON object of version -> base64 key")

	keks = {}
	for version, b64_key in parsed.items():
		try:
			key = base64.b64decode(b64_key, validate=True)
		except Exception as e:
			raise VaultKeyError(f"KEK {version!r} is not valid base64") from e
		if len(key) != DEK_BYTES:
			raise VaultKeyError(f"KEK {version!r} must be {DEK_BYTES} bytes, got {len(key)}")
		keks[version] = key

	if current not in keks:
		raise VaultKeyError(f"{KEK_CURRENT_ENV}={current!r} has no entry in {KEKS_ENV}")

	return keks, current


@dataclass
class EncryptedSecret:
	"""Base64-encoded envelope fields, ready to store on a Vault Secret row."""

	ciphertext: str
	value_nonce: str
	wrapped_dek: str
	dek_nonce: str
	kek_version: str


def encrypt_secret(plaintext: bytes) -> EncryptedSecret:
	keks, current = load_keks()

	dek = AESGCM.generate_key(bit_length=DEK_BYTES * 8)
	value_nonce = os.urandom(NONCE_BYTES)
	ciphertext = AESGCM(dek).encrypt(value_nonce, plaintext, None)

	dek_nonce = os.urandom(NONCE_BYTES)
	wrapped_dek = AESGCM(keks[current]).encrypt(dek_nonce, dek, None)

	return EncryptedSecret(
		ciphertext=base64.b64encode(ciphertext).decode(),
		value_nonce=base64.b64encode(value_nonce).decode(),
		wrapped_dek=base64.b64encode(wrapped_dek).decode(),
		dek_nonce=base64.b64encode(dek_nonce).decode(),
		kek_version=current,
	)


def _unwrap_dek(row, keks: dict[str, bytes]) -> bytes:
	if row.kek_version not in keks:
		raise VaultKeyError(f"KEK version {row.kek_version!r} is not present in {KEKS_ENV}")
	return AESGCM(keks[row.kek_version]).decrypt(
		base64.b64decode(row.dek_nonce), base64.b64decode(row.wrapped_dek), None
	)


def decrypt_secret(row) -> bytes:
	"""Decrypt any object carrying the EncryptedSecret fields (doc or dataclass)."""
	keks, _ = load_keks()
	dek = _unwrap_dek(row, keks)
	return AESGCM(dek).decrypt(
		base64.b64decode(row.value_nonce), base64.b64decode(row.ciphertext), None
	)


def rewrap_dek(row, new_version: str) -> None:
	"""Re-wrap the row's DEK under `new_version`, in place. Ciphertext is untouched."""
	keks, _ = load_keks()
	if new_version not in keks:
		raise VaultKeyError(f"target KEK version {new_version!r} is not present in {KEKS_ENV}")

	dek = _unwrap_dek(row, keks)
	dek_nonce = os.urandom(NONCE_BYTES)
	wrapped = AESGCM(keks[new_version]).encrypt(dek_nonce, dek, None)

	row.wrapped_dek = base64.b64encode(wrapped).decode()
	row.dek_nonce = base64.b64encode(dek_nonce).decode()
	row.kek_version = new_version
