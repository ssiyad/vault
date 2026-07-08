# Copyright (c) 2026, ssiyad and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document

from vault.install import VAULT_ADMIN_ROLE


class VaultSecret(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		ciphertext: DF.LongText | None
		dek_nonce: DF.Data | None
		description: DF.SmallText | None
		kek_version: DF.Data | None
		secret_key: DF.Data
		tags: DF.Data | None
		value_nonce: DF.Data | None
		wrapped_dek: DF.Data | None
	# end: auto-generated types

	pass


@frappe.whitelist()
def set_value(secret_key: str, value: str) -> dict:
	"""Store/replace a secret's value from the desk. The value is write-only."""
	from vault.api import _require_server

	_require_server()
	frappe.only_for(["System Manager", VAULT_ADMIN_ROLE])
	if not value:
		frappe.throw("Value cannot be empty", frappe.ValidationError)

	from vault.audit import log_access
	from vault.backend import get_backend

	get_backend().set(secret_key, value.encode())
	log_access(secret_key, f"UI:{frappe.session.user}", "write", "allow", frappe.local.request_ip)
	return {"key": secret_key, "stored": True}


@frappe.whitelist()
def reveal(secret_key: str) -> str:
	"""Decrypt a secret for an operator. Always leaves an access-log entry."""
	from vault.api import _require_server

	_require_server()
	frappe.only_for(["System Manager", VAULT_ADMIN_ROLE])

	from vault.audit import log_access
	from vault.backend import get_backend

	value = get_backend().get(secret_key)
	log_access(secret_key, f"UI:{frappe.session.user}", "reveal", "allow", frappe.local.request_ip)
	return value.decode()
