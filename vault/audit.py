"""Central access log. Every call is recorded — allows and denials alike.

Denials are committed immediately: the PermissionError raised right after
would otherwise roll the log row back with the rest of the transaction
(frappe rolls back on exceptions and on non-mutating requests).
"""

import frappe


def log_access(
	secret_key: str | None,
	node: str | None,
	action: str,
	result: str,
	source_ip: str | None = None,
	commit: bool = False,
) -> None:
	frappe.get_doc(
		{
			"doctype": "Vault Access Log",
			"secret_key": secret_key,
			"node": node,
			"action": action,
			"result": result,
			"source_ip": source_ip,
		}
	).insert(ignore_permissions=True)
	if commit:
		frappe.db.commit()
