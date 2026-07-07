"""Helpers driven via `bench execute` during end-to-end verification. Not prod code."""

import frappe


def seed_policy(node: str = "test-node", pattern: str = "test/*"):
	if frappe.db.exists("Vault Policy", {"node": node, "key_pattern": pattern}):
		return "policy exists"
	frappe.get_doc(
		{
			"doctype": "Vault Policy",
			"node": node,
			"key_pattern": pattern,
			"enabled": 1,
			"can_read": 1,
			"can_write": 1,
			"can_list": 1,
		}
	).insert(ignore_permissions=True)
	frappe.db.commit()
	return "policy created"


def access_log_tail(limit: int = 10):
	return frappe.get_all(
		"Vault Access Log",
		fields=["name", "secret_key", "node", "action", "result", "source_ip"],
		order_by="creation desc",
		limit=int(limit),
	)


def access_log_count():
	return frappe.db.count("Vault Access Log")


def secret_row(key: str):
	return frappe.db.get_value(
		"Vault Secret",
		key,
		["secret_key", "ciphertext", "value_nonce", "wrapped_dek", "dek_nonce", "kek_version"],
		as_dict=True,
	)


def shim_roundtrip(key: str):
	"""Call the client shim twice; return value + access log delta (should be 1)."""
	from vault.client import clear_cache, get_secret

	clear_cache()
	before = access_log_count()
	first = get_secret(key)
	second = get_secret(key)  # must come from the TTL cache
	after = access_log_count()
	return {"value_ok": first == second, "value": first, "log_delta": after - before}


def backend_set(key: str, value: str):
	from vault.backend import get_backend

	get_backend().set(key, value.encode())
	frappe.db.commit()
	return "stored"


def backend_get(key: str):
	from vault.backend import get_backend

	return get_backend().get(key).decode()


def conf_probe(key: str):
	"""Exercise the VaultConf resolver through the real frappe.conf in this process."""
	from vault.conf import VaultConf

	return {
		"is_vaultconf": isinstance(frappe.local.conf, VaultConf),
		"via_get": frappe.conf.get(key),
		"via_attr": getattr(frappe.conf, key),
	}


def loader_probe(key: str):
	"""Exercise the WRAPPED loader (the web/job path), not the heal branch.

	frappe.init() rebuilds local.conf via frappe.config.get_site_config() on every
	request/job; this calls that same wrapped loader directly and through the cached
	.copy()-downcast path to prove it returns a resolving VaultConf.
	"""
	import frappe.config

	from vault.conf import VaultConf

	cfg = frappe.config.get_site_config(site_path=frappe.get_site_path(), cached=True)
	return {
		"loader_returns_vaultconf": isinstance(cfg, VaultConf),
		"resolved": cfg.get(key),
	}


def conf_fail_closed(key: str):
	"""Point the vault at a dead port and confirm conf.get raises (never returns None)."""
	from vault.client import VaultClientError, clear_cache

	clear_cache()
	frappe.local.conf["vault_url"] = "http://127.0.0.1:1"  # nothing listening
	try:
		frappe.conf.get(key)
		return "NO RAISE — leaked"
	except VaultClientError:
		return "raised VaultClientError (fail closed)"


def set_node_enabled(node: str, enabled: int):
	frappe.db.set_value("Vault Node", node, "enabled", int(enabled))
	frappe.db.commit()
	return f"{node} enabled={enabled}"
