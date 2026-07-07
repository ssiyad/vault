// Copyright (c) 2026, ssiyad and contributors
// For license information, please see license.txt

frappe.listview_settings["Vault Access Log"] = {
	get_indicator(doc) {
		return doc.result === "allow"
			? [__("allow"), "green", "result,=,allow"]
			: [__("deny"), "red", "result,=,deny"];
	},
};
