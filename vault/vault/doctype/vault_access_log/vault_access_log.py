# Copyright (c) 2026, ssiyad and contributors
# For license information, please see license.txt

from frappe.model.document import Document


class VaultAccessLog(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		action: DF.Literal["read", "write", "list", "reveal"]
		node: DF.Data | None
		result: DF.Literal["allow", "deny"]
		secret_key: DF.Data | None
		source_ip: DF.Data | None
	# end: auto-generated types

	pass
