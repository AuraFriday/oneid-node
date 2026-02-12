# 1id

Hardware-anchored identity SDK for AI agents — [1id.com](https://1id.com)

[![npm version](https://img.shields.io/npm/v/1id.svg)](https://www.npmjs.com/package/1id)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## What is 1id.com?

An identity registrar for AI agents. Like a passport office, but for software.

- **TPM-backed**: Agents with a Trusted Platform Module get cryptographic proof of identity
- **Sybil-resistant**: One chip = one identity. No farming.
- **Standards-based**: OAuth2, OIDC, JWT — your existing libraries work
- **Free**: Enrollment and authentication cost nothing

## Installation

```bash
npm install 1id
```

Requires Node.js 18 or later. Zero runtime dependencies.

## Quick Start

```typescript
import oneid from "1id";

// Enroll at declared tier (no TPM required, always works)
const identity = await oneid.enroll({ request_tier: "declared" });
console.log(`Enrolled as ${identity.handle}`);

// Get an OAuth2 token for authentication
const token = await oneid.getToken();
console.log(`Bearer ${token.access_token}`);

// Check current identity
const me = oneid.whoami();
console.log(`I am ${me.handle} (tier: ${me.trust_tier})`);
```

## Trust Tiers

| Tier | Hardware | Sybil Resistant | Trust Level |
|------|----------|-----------------|-------------|
| `sovereign` | TPM (Intel, AMD, Infineon) with valid cert | Yes | Highest |
| `sovereign-portable` | YubiKey / Nitrokey / Feitian with attestation | Yes | Highest |
| `legacy` | Hardware TPM or security key with expired cert | Yes | High |
| `virtual` | VMware / Hyper-V / QEMU vTPM | No | Verified Hardware |
| `enclave` | Apple Secure Enclave (TOFU) | No | Verified Hardware |
| `declared` | None (software keys) | No | Software |

**CRITICAL**: `request_tier` is a REQUIREMENT, not a preference. You get exactly what you ask for, or an exception. No silent fallbacks.

## API

### `oneid.enroll(options)`

Enroll this agent with 1id.com.

```typescript
const identity = await oneid.enroll({
  request_tier: "declared",           // REQUIRED: trust tier
  key_algorithm: "ed25519",           // Optional: ed25519 (default), ecdsa-p256, rsa-2048, etc.
  requested_handle: "my-agent",       // Optional: vanity handle (without @)
  operator_email: "human@example.com" // Optional: human contact
});
```

### `oneid.getToken()`

Get a valid OAuth2 access token (cached, auto-refreshes).

```typescript
const token = await oneid.getToken();
// Use token.access_token as a Bearer token
```

### `oneid.whoami()`

Read the local identity (no network call).

```typescript
const me = oneid.whoami();
// me.internal_id, me.handle, me.trust_tier, etc.
```

### `oneid.credentials_exist()`

Check if the agent has enrolled.

```typescript
if (!oneid.credentials_exist()) {
  await oneid.enroll({ request_tier: "declared" });
}
```

## Error Handling

All errors extend `OneIDError`:

```typescript
import { OneIDError, NoHSMError, EnrollmentError, NetworkError } from "1id";

try {
  await oneid.enroll({ request_tier: "sovereign" });
} catch (e) {
  if (e instanceof NoHSMError) {
    console.log("No TPM found — try 'declared' tier");
  } else if (e instanceof NetworkError) {
    console.log("Server unreachable — check connection");
  }
}
```

## Architecture

The SDK uses a two-tier architecture:

1. **TypeScript SDK** (this package) — handles enrollment orchestration, credential storage, OAuth2 token management, and software key operations using Node.js built-in `crypto`
2. **Go binary** (`oneid-enroll`) — handles all TPM/HSM hardware operations. Auto-downloaded from [GitHub releases](https://github.com/AuraFriday/oneid-enroll/releases) when needed

For `declared` tier enrollment, only the TypeScript SDK is needed. For `sovereign` (TPM) tier, the Go binary is automatically fetched.

## Credential Storage

Credentials are stored at:
- **Windows**: `%APPDATA%\oneid\credentials.json`
- **Linux/macOS**: `~/.config/oneid/credentials.json`

Permissions are set to owner-only (0600 on Unix).

## Python SDK

The Python equivalent is available as [`oneid`](https://pypi.org/project/oneid/) on PyPI:

```bash
pip install oneid
```

Both SDKs share the same API design and credential format.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Links

- [1id.com](https://1id.com) — Service homepage
- [Enrollment guide](https://1id.com/enroll.md) — Machine-readable enrollment instructions
- [Python SDK](https://pypi.org/project/oneid/) — `pip install oneid`
- [Go binary](https://github.com/AuraFriday/oneid-enroll) — TPM/HSM helper
