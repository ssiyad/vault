# Copyright (c) 2026, ssiyad and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class VaultNode(Document):
	pass


@frappe.whitelist()
def issue_token(node_name: str) -> str:
	"""Mint a token for the node; shown once in the UI, never recoverable."""
	from vault.api import _require_server
	from vault.auth import issue_node_token

	_require_server()

	return issue_node_token(node_name)
