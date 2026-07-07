# Copyright (c) 2026, ssiyad and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class VaultPolicy(Document):
	def validate(self):
		if not (self.can_read or self.can_write or self.can_list):
			frappe.throw("A policy must allow at least one action (read, write or list).")
