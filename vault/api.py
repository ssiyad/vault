"""Node-facing vault endpoints. POST-only, JSON in transit.

Bodies are parsed straight from the raw request (`frappe.request.get_data()`),
never via form_dict: guest whitelisted methods HTML-sanitize form_dict values,
which would corrupt secret payloads containing markup characters.

Failures log a denial (committed before raising — exceptions roll back the
transaction) and raise a bare PermissionError: no hint whether the token was
bad, the node disabled, or the key out of policy.
"""

import json

import frappe
from frappe.rate_limiter import rate_limit

from vault.audit import log_access
from vault.auth import verify_node_token
from vault.backend import get_backend
from vault.policy import is_allowed


def _require_server() -> None:
	"""Only sites flagged vault_server serve the vault. Everywhere else the same
	app is installed purely for its client shim, and these endpoints don't exist."""
	if not frappe.conf.get("vault_server"):
		raise frappe.DoesNotExistError


def _deny(key: str | None, node: str | None, action: str) -> None:
	log_access(key, node, action, "deny", frappe.local.request_ip, commit=True)
	raise frappe.PermissionError


def _allow_log(key: str | None, node: str, action: str) -> None:
	log_access(key, node, action, "allow", frappe.local.request_ip)


def _read_body() -> dict:
	try:
		body = json.loads(frappe.request.get_data() or b"")
	except (json.JSONDecodeError, UnicodeDecodeError):
		body = None
	if not isinstance(body, dict):
		frappe.throw("Request body must be a JSON object", frappe.ValidationError)

	# Frappe also parses the JSON body into form_dict, and exception/monitor
	# logging dumps form_dict (its name-based masking misses a field called
	# "value"). We only ever read the raw body, so mask every body field.
	for field in body:
		if field in frappe.local.form_dict:
			frappe.local.form_dict[field] = "********"

	return body


TOKEN_HEADER = "X-Vault-Token"
# Not `Authorization: Bearer`: frappe's validate_auth() rejects any two-part
# Authorization header that doesn't resolve to a Frappe user/OAuth session,
# before whitelisted methods run. A dedicated header (same convention as
# HashiCorp Vault) keeps node identity decoupled from User records.


def _authorize(key: str | None, action: str) -> str:
	token = (frappe.get_request_header(TOKEN_HEADER) or "").strip()

	node = verify_node_token(token)
	if not node:
		_deny(key, None, action)
	if not key or not is_allowed(node, key, action, frappe.local.request_ip):
		_deny(key, node, action)
	return node


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=60, seconds=60)
def get() -> dict:
	_require_server()
	body = _read_body()
	key = body.get("key")
	node = _authorize(key, "read")

	if not frappe.db.exists("Vault Secret", key):
		_deny(key, node, "read")

	value = get_backend().get(key)
	_allow_log(key, node, "read")
	return {"key": key, "value": value.decode()}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=60, seconds=60)
def set_secret() -> dict:
	_require_server()
	body = _read_body()
	key = body.get("key")
	value = body.get("value")
	node = _authorize(key, "write")

	if not isinstance(value, str) or not value:
		frappe.throw("'value' must be a non-empty string", frappe.ValidationError)

	get_backend().set(key, value.encode())
	_allow_log(key, node, "write")
	return {"key": key, "stored": True}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=60, seconds=60)
def list_keys() -> dict:
	_require_server()
	body = _read_body()
	prefix = body.get("prefix")
	node = _authorize(prefix, "list")

	keys = get_backend().list(prefix)
	_allow_log(prefix, node, "list")
	return {"prefix": prefix, "keys": keys}
