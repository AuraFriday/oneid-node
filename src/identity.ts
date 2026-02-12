/**
 * Identity and Token data models for the 1id.com Node.js SDK.
 *
 * These types represent the agent's enrolled identity and OAuth2 tokens.
 * They are returned by enroll(), whoami(), and getToken() respectively.
 */

/**
 * Trust tiers assigned by 1id.com based on hardware attestation.
 *
 * Ordered from highest to lowest Sybil resistance:
 * - sovereign: Non-portable hardware (TPM), manufacturer-attested, current cert
 * - sovereign-portable: Portable hardware (YubiKey/Nitrokey), manufacturer-attested
 * - legacy: Was sovereign/sovereign-portable, but manufacturer cert expired
 * - virtual: Virtual TPM (VMware/Hyper-V), hypervisor-attested
 * - enclave: Apple Secure Enclave, TOFU (no attestation PKI)
 * - declared: Software-only, no hardware proof, self-asserted
 */
export enum TrustTier {
  SOVEREIGN = "sovereign",
  SOVEREIGN_PORTABLE = "sovereign-portable",
  LEGACY = "legacy",
  VIRTUAL = "virtual",
  ENCLAVE = "enclave",
  DECLARED = "declared",
}

/**
 * Supported key algorithms for declared-tier software keys.
 */
export enum KeyAlgorithm {
  ED25519 = "ed25519",
  ECDSA_P256 = "ecdsa-p256",
  ECDSA_P384 = "ecdsa-p384",
  RSA_2048 = "rsa-2048",
  RSA_4096 = "rsa-4096",
}

/** The default key algorithm for declared-tier enrollment. */
export const DEFAULT_KEY_ALGORITHM = KeyAlgorithm.ED25519;

/**
 * Types of hardware security modules supported by 1id.com.
 */
export enum HSMType {
  TPM = "tpm",
  YUBIKEY = "yubikey",
  NITROKEY = "nitrokey",
  FEITIAN = "feitian",
  SOLOKEYS = "solokeys",
  SECURE_ENCLAVE = "secure_enclave",
  SOFTWARE = "software",
}

/**
 * Represents an enrolled 1id.com agent identity.
 *
 * Returned by enroll() and whoami(). All fields are readonly.
 */
export interface Identity {
  /** Permanent unique identifier (e.g., '1id_a7b3c9d2'). Never changes. */
  readonly internal_id: string;
  /** Display name (e.g., '@clawdia' or '@1id_a7b3c9d2'). */
  readonly handle: string;
  /** The trust level assigned based on hardware attestation. */
  readonly trust_tier: TrustTier;
  /** Type of HSM used for enrollment, or null for declared tier. */
  readonly hsm_type: HSMType | null;
  /** Manufacturer code (e.g., 'INTC', 'Yubico'), or null. */
  readonly hsm_manufacturer: string | null;
  /** When this identity was first created. */
  readonly enrolled_at: Date;
  /** Number of HSMs currently linked to this identity. */
  readonly device_count: number;
  /** The key algorithm used for this identity's signing key. */
  readonly key_algorithm: KeyAlgorithm;
}

/**
 * Represents an OAuth2 access token from 1id.com / Keycloak.
 *
 * Returned by getToken(). The accessToken is a signed JWT
 * containing the agent's identity claims (sub, handle, trust_tier, etc.).
 */
export interface Token {
  /** The JWT access token string (Bearer token). */
  readonly access_token: string;
  /** Always 'Bearer'. */
  readonly token_type: string;
  /** When this token expires (UTC). */
  readonly expires_at: Date;
  /** Refresh token for obtaining new access tokens, or null. */
  readonly refresh_token: string | null;
}

/**
 * Check whether a token is still valid based on its expiry time.
 *
 * Returns true if the token's expiry time is in the future.
 * Does NOT verify the JWT signature or check revocation.
 */
export function this_token_has_not_yet_expired(token: Token): boolean {
  return new Date() < token.expires_at;
}

/**
 * Format a token for use in an HTTP Authorization header.
 *
 * Returns a string in the format 'Bearer <access_token>'.
 */
export function format_authorization_header_value(token: Token): string {
  return `${token.token_type} ${token.access_token}`;
}

/**
 * Format an Identity as a human-readable string.
 */
export function format_identity_as_display_string(identity: Identity): string {
  return `${identity.handle} (tier: ${identity.trust_tier}, id: ${identity.internal_id})`;
}
