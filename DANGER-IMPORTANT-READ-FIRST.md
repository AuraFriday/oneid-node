# DANGER -- DO NOT EDIT FILES IN THIS FOLDER

**Last synced: 2026-02-12T05:23:41Z**

This folder is a **read-only mirror** of the canonical source tree at
`websites/1id.com/` in the private 1id project repository.

## Files here are OVERWRITTEN every time the Makefile runs

Any changes you make directly in this folder **will be lost** the next
time someone runs `make github` from the source tree.

## How to make changes

1. Edit the source files in `websites/1id.com/` (the private repo)
2. Test and commit there as usual (`git push` auto-deploys to production)
3. Run the publish Makefile to sync changes to these GitHub repos:

```bash
cd websites/1id.com/
make github          # sync all repos
make github-push     # push all to GitHub
```

Or sync just one repo:

```bash
make github-sdk      # sync oneid-sdk only
make github-enroll   # sync oneid-enroll only
make github-site     # sync 1id.com only
```

## Repo mapping

| GitHub repo | Source folder | What it contains |
|-------------|--------------|------------------|
| `AuraFriday/oneid-sdk` | `sdk/oneid-sdk/` | Python SDK (PyPI: `oneid-sdk`) |
| `AuraFriday/oneid-enroll` | `sdk/oneid-enroll/` | Go binary for TPM/HSM operations |
| `AuraFriday/oneid-node` | *(future)* | Node.js SDK |
| `AuraFriday/1id.com` | `public_html/`, `api/`, `keycloak-spi/`, `config/` | Website + API + Keycloak SPI |
