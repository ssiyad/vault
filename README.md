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

In the client site's `site_config.json`:

```json
"vault_url": "https://vault.example.com",
"vault_token": "svlt_..."
```

App code then reads secrets with one line:

```python
frappe.get_secret("siteb/stripe_key")   # or: from vault.client import get_secret
```

The client caches values **in memory only** with a short TTL (default 60s), so brief
vault outages don't break request serving; past the TTL it fails closed. Plaintext
never touches the client's disk, database or redis. Do **not** set `vault_server`
or the KEK variables on client machines.

To move existing plaintext secrets out of a client's `site_config.json`:

```sh
bench --site siteb.example.com vault-migrate            # dry run
bench --site siteb.example.com vault-migrate --commit   # apply
```

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
