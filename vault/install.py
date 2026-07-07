import frappe

VAULT_ADMIN_ROLE = "Vault Admin"


def ensure_roles():
	"""Create the Vault Admin role. Idempotent; runs on install and migrate."""
	if not frappe.db.exists("Role", VAULT_ADMIN_ROLE):
		frappe.get_doc(
			{
				"doctype": "Role",
				"role_name": VAULT_ADMIN_ROLE,
				"desk_access": 1,
			}
		).insert(ignore_permissions=True)


def after_install():
	ensure_roles()


def after_migrate():
	ensure_roles()
