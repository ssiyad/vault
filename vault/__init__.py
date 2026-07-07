__version__ = "0.0.1"


def _install_conf_resolver() -> None:
	"""Route frappe.conf reads through VaultConf so `vault/`-prefixed values resolve."""
	from vault.conf import install

	install()


try:
	_install_conf_resolver()
except ImportError:
	# outside a bench environment (e.g. standalone crypto tests)
	pass
