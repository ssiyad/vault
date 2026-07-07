// Copyright (c) 2026, ssiyad and contributors
// For license information, please see license.txt

frappe.ui.form.on("Vault Node", {
	refresh(frm) {
		if (frm.is_new()) return;

		frm.add_custom_button(__("Issue Token"), () => {
			frappe.confirm(
				__("Issue a new token? Any previously issued token for this node stops working."),
				() => {
					frappe
						.call({
							method: "vault.vault.doctype.vault_node.vault_node.issue_token",
							args: { node_name: frm.doc.name },
						})
						.then((r) => {
							frappe.msgprint({
								title: __("Node Token — shown only once"),
								indicator: "orange",
								message: `<pre>${frappe.utils.escape_html(r.message)}</pre>${__(
									"Put it in the node's site_config as <code>vault_token</code>. It cannot be recovered later."
								)}`,
							});
							frm.reload_doc();
						});
				}
			);
		});
	},
});
