"""Node identity: token issuance and verification.

Token format: svlt_<node_id>_<secret>. node_id is a public lookup handle;
the secret is 256 bits of CSPRNG output. The raw token is returned exactly
once at issuance — only its SHA-256 lands in the database (Data field, unique
index → O(1) lookup; slow hashes buy nothing against 256-bit entropy).
"""

import hashlib
import hmac

import frappe
import frappe.utils

from vault.install import VAULT_ADMIN_ROLE

TOKEN_PREFIX = "svlt"


def _hash_token(token: str) -> str:
	return hashlib.sha256(token.encode()).hexdigest()


def issue_node_token(node_name: str) -> str:
	"""Create (or re-key) a Vault Node and return its raw token, shown exactly once."""
	frappe.only_for(["System Manager", VAULT_ADMIN_ROLE])

	node_id = frappe.generate_hash(length=12)
	secret = frappe.generate_hash(length=48)
	token = f"{TOKEN_PREFIX}_{node_id}_{secret}"

	if frappe.db.exists("Vault Node", node_name):
		doc = frappe.get_doc("Vault Node", node_name)
	else:
		doc = frappe.new_doc("Vault Node")
		doc.node_name = node_name
		doc.enabled = 1
	doc.node_id = node_id
	doc.token_hash = _hash_token(token)
	doc.save()

	return token


def verify_node_token(presented: str) -> str | None:
	"""Return the Vault Node name for a valid token, else None. Never say why."""
	try:
		prefix, node_id, _secret = presented.split("_", 2)
	except (ValueError, AttributeError):
		return None
	if prefix != TOKEN_PREFIX:
		return None

	row = frappe.db.get_value(
		"Vault Node",
		{"node_id": node_id, "enabled": 1},
		["name", "token_hash", "expires_on"],
		as_dict=True,
	)
	if not row or not row.token_hash:
		return None
	if row.expires_on and frappe.utils.now_datetime() > row.expires_on:
		return None
	if not hmac.compare_digest(_hash_token(presented), row.token_hash):
		return None

	frappe.db.set_value(
		"Vault Node", row.name, "last_seen", frappe.utils.now_datetime(), update_modified=False
	)
	return row.name
