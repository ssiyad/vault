# Vault

A Frappe-native, cluster-central secrets service. One site (the **vault server**)
holds versioned master keys and does all crypto — AES-256-GCM envelope encryption,
prefix policies (deny-by-default), a central access log. Every other site is a thin
**client** that fetches secrets over HTTPS with a per-node token.

The same app is installed on every machine; a site's role comes from configuration.
Client installs carry the server code inertly — the API and admin entry points refuse
to serve (404) unless the site is flagged as the server.

## Server setup (one site per cluster)

```sh
bench get-app vault && bench --site vault.example.com install-app vault
bench --site vault.example.com set-config vault_server 1
```

Export the master keys in the environment of every process serving the site
(the KEKs never live in a file or the database — strict, no fallback):

```sh
export VAULT_KEKS='{"v1": "<base64 32-byte key>"}'
export VAULT_KEK_CURRENT=v1
```

Generate a key with:
`python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"`

Then, per client machine:

1. `bench --site vault.example.com vault-issue-token <node-name>` — the token is
   printed **once**; deliver it to the node out of band (this is secret-zero).
   Or use the *Issue Token* button on the Vault Node form.
2. Create a **Vault Policy** for the node: key pattern (e.g. `siteb/*`) + allowed
   actions. No matching policy means deny.

## Client machine setup

```sh
bench get-app vault && bench --site siteb.example.com install-app vault
```

In the client site's `site_config.json`, set the connection and store each secret as a
`vault/`-prefixed **reference value** (not the secret itself):

```json
"vault_url": "https://vault.example.com",
"vault_token": "svlt_...",
"stripe_key": "vault/siteb/stripe_key"
```

App code then reads secrets through the normal config accessor — no vault-specific API:

```python
frappe.conf.get("stripe_key")   # -> the decrypted secret, fetched from the vault
frappe.conf.get("some_plain_key")  # -> plain values are returned untouched
```

Any config value beginning with `vault/` is resolved on read: the prefix is stripped and
the remainder (`siteb/stripe_key`) is the vault key. Values without the prefix behave
exactly as stock Frappe. The client caches resolved values **in memory only** with a
short TTL (default 60s), so brief vault outages don't break request serving; past the TTL
it **fails closed** (raises rather than returning a stale or empty secret). Plaintext
never touches the client's disk, database or redis. Do **not** set `vault_server` or the
KEK variables on client machines.

> Note: web workers cache `site_config.json` for ~60s (`frappe/config.py`), so a newly
> added reference can take up to a minute to appear in running workers.

To move existing plaintext secrets out of a client's `site_config.json`:

```sh
bench --site siteb.example.com vault-migrate            # dry run
bench --site siteb.example.com vault-migrate --commit   # apply
```

`--commit` pushes each detected secret to the vault and rewrites its `site_config.json`
value in place to `vault/<node>/<key>`, so existing `frappe.conf.get(...)` calls keep
working unchanged. Re-running is a no-op (already-referenced values are skipped).

## Rotating the master key

Add the new version to `VAULT_KEKS` (keep the old one), set `VAULT_KEK_CURRENT` to it,
restart, then:

```sh
bench --site vault.example.com vault-rotate-kek v2
```

Only the small wrapped data keys are re-encrypted — stored ciphertext never moves.
The command is resumable; once no row references the old version, drop it from
`VAULT_KEKS`.

## Notes

- Nodes authenticate with an `X-Vault-Token` header (not `Authorization`, which
  Frappe reserves for User/OAuth sessions). Raw tokens are never stored — only a
  SHA-256 hash. Revoke a node by unchecking *Enabled*; the next request is denied
  and logged.
- Every access — allowed or denied, API or UI reveal — lands in **Vault Access Log**.
- Avoid passing secret values as CLI arguments (`bench set-config my_key ...`):
  bench logs command lines to `logs/bench.log`.
