# Copyright (c) 2026, ssiyad and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class VaultPolicy(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		can_list: DF.Check
		can_read: DF.Check
		can_write: DF.Check
		enabled: DF.Check
		ip_allowlist: DF.SmallText | None
		key_pattern: DF.Data
		node: DF.Link
	# end: auto-generated types

	def validate(self):
		if not (self.can_read or self.can_write or self.can_list):
			frappe.throw("A policy must allow at least one action (read, write or list).")
