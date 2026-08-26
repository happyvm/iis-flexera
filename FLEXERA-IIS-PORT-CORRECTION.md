# Flexera IIS Port Guidance Correction

This note corrects an ambiguity in the initial `FLEXERA-IIS-BASELINE.md` draft.

For **IIS web server mode**, current Flexera Inventory Beacon documentation states that target devices recognize the default protocol ports:

```text
HTTP  = 80
HTTPS = 443
```

The Flexera **self-hosted web server** is different: its port is configurable.

Therefore, for the IIS monitoring/security audit:

- discover and record all actual bindings,
- do not silently ignore a custom binding,
- but do **not** classify an arbitrary custom IIS port as equivalent to the documented Flexera IIS configuration,
- report a custom port used for Beacon-agent IIS communication as a compatibility item requiring validation against the deployed Flexera release.

This correction supersedes wording in the initial baseline draft that said custom IIS ports should simply be treated as valid.

For implementation and security decisions, [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md) is authoritative.

Reference:

https://docs.flexera.com/fnms/inventory-beacon-overview/local-web-server-tab/configuring-inventory-collection
