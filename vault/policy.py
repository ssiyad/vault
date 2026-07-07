"""Prefix-based authorization. Deny-by-default: no matching policy, no access."""

import frappe

ACTION_FIELDS = {
	"read": "can_read",
	"write": "can_write",
	"list": "can_list",
}


def _pattern_matches(pattern: str, key: str) -> bool:
	pattern = (pattern or "").strip()
	if not pattern:
		return False
	if pattern.endswith("*"):
		return key.startswith(pattern[:-1])
	return key == pattern


def _ip_allowed(allowlist: str | None, source_ip: str | None) -> bool:
	if not allowlist or not allowlist.strip():
		return True
	allowed = {ip.strip() for ip in allowlist.replace("\n", ",").split(",") if ip.strip()}
	return source_ip in allowed


def is_allowed(node: str, key: str, action: str, source_ip: str | None = None) -> bool:
	action_field = ACTION_FIELDS.get(action)
	if not action_field:
		return False

	node_allowlist = frappe.db.get_value("Vault Node", node, "ip_allowlist")
	if not _ip_allowed(node_allowlist, source_ip):
		return False

	policies = frappe.get_all(
		"Vault Policy",
		filters={"node": node, "enabled": 1, action_field: 1},
		fields=["key_pattern", "ip_allowlist"],
	)
	return any(
		_pattern_matches(p.key_pattern, key) and _ip_allowed(p.ip_allowlist, source_ip)
		for p in policies
	)
