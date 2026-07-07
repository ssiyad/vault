"""The node-side runtime surface: frappe.get_secret(key).

Runs inside every client site's app code. Reads this node's token from its
own site_config (vault_url + vault_token — secret-zero, provisioned out of
band), calls the central vault over HTTPS and caches the value in memory
with a short TTL so brief vault blips don't break request serving. Past the
TTL it fails closed. Plaintext never touches disk, redis or the database.
"""

import time

import requests

import frappe

_cache: dict[str, tuple[str, float]] = {}  # key -> (value, expires_at); process-local


class VaultClientError(Exception):
	pass


def get_secret(key: str, ttl: int = 60) -> str:
	hit = _cache.get(key)
	if hit and hit[1] > time.monotonic():
		return hit[0]

	value = _fetch(key)
	_cache[key] = (value, time.monotonic() + ttl)
	return value


def _fetch(key: str) -> str:
	base = frappe.conf.get("vault_url")
	token = frappe.conf.get("vault_token")
	if not base or not token:
		raise VaultClientError("vault_url and vault_token must be set in site_config")

	try:
		resp = requests.post(
			f"{base.rstrip('/')}/api/method/vault.api.get",
			json={"key": key},
			headers={"X-Vault-Token": token},
			timeout=5,
		)
		resp.raise_for_status()
	except requests.RequestException as e:
		raise VaultClientError(f"vault request for {key!r} failed") from e

	return resp.json()["message"]["value"]


def clear_cache() -> None:
	_cache.clear()
