"""Operator/provisioning tooling — run by humans or scripts, never by nodes.

vault-issue-token  mint a node token (secret-zero, delivered out of band)
vault-migrate      move plaintext site_config secrets into the vault (dry-run default)
vault-rotate-kek   re-wrap every DEK under a new master key version (resumable)
"""

import json
import os

import click

import frappe
from frappe.commands import get_site, pass_context

from vault.conf import VAULT_PREFIX

SECRETISH = ("key", "secret", "token", "password", "passwd", "credential")
SKIP_PREFIXES = ("db_", "vault_")
SKIP_KEYS = {"encryption_key", "admin_password", "host_name"}


def _connected(context):
	site = get_site(context)
	frappe.init(site=site)
	frappe.connect()
	return site


@click.command("vault-issue-token")
@click.argument("node_name")
@pass_context
def vault_issue_token(context, node_name):
	"""Issue a node token for NODE_NAME (re-keys the node if it exists). Shown once."""
	_connected(context)
	try:
		from vault.auth import issue_node_token

		token = issue_node_token(node_name)
		frappe.db.commit()
		click.secho(token, fg="green")
		click.echo("Store this now — it will not be shown again.")
	finally:
		frappe.destroy()


def _secret_candidates(conf: dict) -> dict[str, str]:
	candidates = {}
	for key, value in conf.items():
		if key in SKIP_KEYS or key.startswith(SKIP_PREFIXES):
			continue
		if not isinstance(value, str) or not value:
			continue
		if value.startswith(VAULT_PREFIX):  # already migrated
			continue
		if any(marker in key.lower() for marker in SECRETISH):
			candidates[key] = value
	return candidates


@click.command("vault-migrate")
@click.option("--prefix", default=None, help="Vault key prefix; defaults to the site name.")
@click.option("--commit", "apply_changes", is_flag=True, help="Apply. Without this: dry run.")
@pass_context
def vault_migrate(context, prefix, apply_changes):
	"""Move plaintext secrets from this site's site_config.json into the vault."""
	import requests

	site = _connected(context)
	try:
		config_path = frappe.get_site_path("site_config.json")
		with open(config_path) as f:
			site_config = json.load(f)

		vault_url = site_config.get("vault_url")
		vault_token = site_config.get("vault_token")
		if not vault_url or not vault_token:
			raise click.ClickException("vault_url and vault_token must be set in site_config.json")

		candidates = _secret_candidates(site_config)
		if not candidates:
			click.echo("No plaintext secret candidates found in site_config.json.")
			return

		prefix = prefix or site
		mode = "MIGRATE" if apply_changes else "DRY RUN (use --commit to apply)"
		click.secho(f"{mode} — {len(candidates)} candidate(s) in {config_path}", bold=True)

		for key, value in candidates.items():
			vault_key = f"{prefix}/{key}"
			click.echo(f"  {key}  ->  {vault_key}")
			if not apply_changes:
				continue

			resp = requests.post(
				f"{vault_url.rstrip('/')}/api/method/vault.api.set_secret",
				json={"key": vault_key, "value": value},
				headers={"X-Vault-Token": vault_token},
				timeout=10,
			)
			if resp.status_code != 200:
				raise click.ClickException(
					f"vault refused write for {vault_key!r} (HTTP {resp.status_code}); "
					"check the node's write policy. Config left untouched."
				)
			site_config[key] = f"{VAULT_PREFIX}{vault_key}"

		if apply_changes:
			with open(config_path, "w") as f:
				json.dump(site_config, f, indent=1, sort_keys=True)
			click.secho("Done. Plaintext values replaced with vault references.", fg="green")
			click.echo("frappe.conf.get(...) now resolves these keys from the vault.")
	finally:
		frappe.destroy()


@click.command("vault-rotate-kek")
@click.argument("new_version")
@pass_context
def vault_rotate_kek(context, new_version):
	"""Re-wrap all DEKs under NEW_VERSION (from VAULT_KEKS). Values never move.

	Resumable: rows are committed one by one; mixed versions mid-run are valid.
	"""
	_connected(context)
	try:
		from vault.crypto import load_keks, rewrap_dek

		keks, _current = load_keks()
		if new_version not in keks:
			raise click.ClickException(f"{new_version!r} not present in VAULT_KEKS")

		pending = frappe.get_all(
			"Vault Secret",
			filters={"kek_version": ("!=", new_version)},
			pluck="name",
		)
		if not pending:
			click.echo(f"All secrets already on {new_version}.")
			return

		for i, name in enumerate(pending, 1):
			row = frappe.db.get_value(
				"Vault Secret",
				name,
				["wrapped_dek", "dek_nonce", "kek_version"],
				as_dict=True,
			)
			rewrap_dek(row, new_version)
			frappe.db.set_value(
				"Vault Secret",
				name,
				{
					"wrapped_dek": row.wrapped_dek,
					"dek_nonce": row.dek_nonce,
					"kek_version": row.kek_version,
				},
			)
			frappe.db.commit()
			click.echo(f"  [{i}/{len(pending)}] {name}")

		click.secho(f"Rotated {len(pending)} secret(s) to {new_version}.", fg="green")
		click.echo("Old KEK versions can be dropped from VAULT_KEKS once unreferenced.")
	finally:
		frappe.destroy()


commands = [vault_issue_token, vault_migrate, vault_rotate_kek]
