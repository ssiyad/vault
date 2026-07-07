__version__ = "0.0.1"


def _expose_get_secret() -> None:
	"""Make frappe.get_secret available everywhere once the app is importable."""
	import frappe

	from vault.client import get_secret

	frappe.get_secret = get_secret


try:
	_expose_get_secret()
except ImportError:
	# outside a bench environment (e.g. standalone crypto tests)
	pass
