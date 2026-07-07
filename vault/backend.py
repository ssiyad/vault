"""Storage engines behind the vault API.

The API, policies, access log and tooling talk to a `SecretsBackend`;
`LocalBackend` (AES-256-GCM envelope, Vault Secret doctype) is the engine
shipped today. `RemoteBackend` is the seam for delegating storage to an
external engine (e.g. OpenBao) in v2 without touching the Frappe surface.
"""

import frappe

from vault.crypto import decrypt_secret, encrypt_secret


class SecretsBackend:
	def get(self, key: str) -> bytes:
		raise NotImplementedError

	def set(self, key: str, value: bytes) -> None:
		raise NotImplementedError

	def list(self, prefix: str) -> list[str]:
		raise NotImplementedError

	def delete(self, key: str) -> None:
		raise NotImplementedError


class LocalBackend(SecretsBackend):
	"""Envelope-encrypted storage in the Vault Secret doctype."""

	def get(self, key: str) -> bytes:
		doc = frappe.get_doc("Vault Secret", key)
		return decrypt_secret(doc)

	def set(self, key: str, value: bytes) -> None:
		envelope = encrypt_secret(value)
		if frappe.db.exists("Vault Secret", key):
			doc = frappe.get_doc("Vault Secret", key)
		else:
			doc = frappe.new_doc("Vault Secret")
			doc.secret_key = key
		doc.update(
			{
				"ciphertext": envelope.ciphertext,
				"value_nonce": envelope.value_nonce,
				"wrapped_dek": envelope.wrapped_dek,
				"dek_nonce": envelope.dek_nonce,
				"kek_version": envelope.kek_version,
			}
		)
		doc.save(ignore_permissions=True)

	def list(self, prefix: str) -> list[str]:
		return frappe.get_all(
			"Vault Secret",
			filters={"secret_key": ("like", f"{prefix}%")},
			pluck="secret_key",
			order_by="secret_key",
		)

	def delete(self, key: str) -> None:
		frappe.delete_doc("Vault Secret", key, ignore_permissions=True)


class RemoteBackend(SecretsBackend):
	"""v2 seam: same Frappe API/UI/policies, storage delegated to an external engine."""


def get_backend() -> SecretsBackend:
	return LocalBackend()
