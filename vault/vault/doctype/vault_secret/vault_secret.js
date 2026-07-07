// Copyright (c) 2026, ssiyad and contributors
// For license information, please see license.txt

frappe.ui.form.on("Vault Secret", {
	refresh(frm) {
		if (frm.is_new()) return;

		frm.add_custom_button(__("Set Value"), () => {
			frappe.prompt(
				{
					fieldname: "value",
					fieldtype: "Password",
					label: __("Secret Value"),
					reqd: 1,
				},
				(values) => {
					frappe
						.call({
							method: "vault.vault.doctype.vault_secret.vault_secret.set_value",
							args: { secret_key: frm.doc.name, value: values.value },
						})
						.then(() => {
							frappe.show_alert({ message: __("Encrypted and stored"), indicator: "green" });
							frm.reload_doc();
						});
				},
				__("Set Secret Value"),
				__("Encrypt & Store")
			);
		});

		if (frm.doc.ciphertext) {
			frm.add_custom_button(__("Reveal"), () => {
				frappe
					.call({
						method: "vault.vault.doctype.vault_secret.vault_secret.reveal",
						args: { secret_key: frm.doc.name },
					})
					.then((r) => {
						frappe.msgprint({
							title: __("Secret Value (access logged)"),
							indicator: "orange",
							message: `<pre>${frappe.utils.escape_html(r.message)}</pre>`,
						});
					});
			});
		}
	},
});
