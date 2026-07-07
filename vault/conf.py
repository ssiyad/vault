"""Resolve vault-backed secrets through the native `frappe.conf` accessor.

A config value that is a string beginning with ``vault/`` is a reference, not a
secret: the prefix is stripped and the remainder is fetched from the vault via
the client shim (lazy, in-memory TTL cache, fail-closed). Every other value is
returned untouched. This makes migration transparent — code keeps calling
``frappe.conf.get("mailgun_api_key")`` and gets the decrypted value.

`frappe.conf` is a LocalProxy to `frappe.local.conf`, a `_dict` rebuilt on every
`frappe.init()`. We install by wrapping the config loader so every future conf is
a `VaultConf`, and by healing the conf already loaded in the current process.
"""

import frappe.config
from frappe.types.frappedict import _dict

VAULT_PREFIX = "vault/"


def _resolve(value):
	if isinstance(value, str) and value.startswith(VAULT_PREFIX):
		from vault.client import get_secret

		return get_secret(value[len(VAULT_PREFIX) :])
	return value


class VaultConf(_dict):
	"""A site-config dict that resolves ``vault/``-prefixed string values on read."""

	__slots__ = ()

	def get(self, key, default=None):
		return _resolve(dict.get(self, key, default))

	def __getitem__(self, key):
		return _resolve(dict.__getitem__(self, key))

	def __getattr__(self, key):
		# _dict binds __getattr__ to raw dict.get; mirror that (None on miss, no
		# recursion) while resolving vault references so attribute access matches .get().
		return _resolve(dict.get(self, key))

	def copy(self):
		# _dict.copy() downcasts to plain _dict; keep our type.
		return VaultConf(self)


def install() -> None:
	"""Idempotently route site-config reads through VaultConf. Safe outside a bench."""
	orig = frappe.config.get_site_config
	if not getattr(orig, "_vault_wrapped", False):

		def get_site_config(*args, **kwargs):
			return VaultConf(orig(*args, **kwargs))

		get_site_config._vault_wrapped = True
		frappe.config.get_site_config = get_site_config
		# frappe.init() re-imports from frappe.config each call, but other call sites
		# use the lazily-resolved frappe.get_site_config export — keep it in sync.
		if "get_site_config" in vars(frappe):
			frappe.get_site_config = get_site_config

	try:
		conf = getattr(frappe.local, "conf", None)
		if conf is not None and not isinstance(conf, VaultConf):
			frappe.local.conf = VaultConf(conf)
	except Exception:
		# no request/site context at import time (e.g. standalone tests) — nothing to heal
		pass
