/**
 * 1id.com SDK -- Hardware-anchored identity for AI agents.
 *
 * Quick start:
 *
 *     import oneid from "1id";
 *
 *     // Enroll at declared tier (no HSM, always works)
 *     const identity = await oneid.enroll({ request_tier: "declared" });
 *     console.log(`Enrolled as ${identity.handle}`);
 *
 *     // Get an OAuth2 token for authentication
 *     const token = await oneid.getToken();
 *     console.log(`Bearer ${token.access_token}`);
 *
 *     // Check current identity
 *     const me = oneid.whoami();
 *
 * Trust tiers (request_tier parameter):
 *     'sovereign'          -- TPM hardware, manufacturer-attested
 *     'sovereign-portable' -- YubiKey/Nitrokey, manufacturer-attested
 *     'declared'           -- Software keys, no hardware proof
 *
 * CRITICAL: request_tier is a REQUIREMENT, not a preference.
 * You get exactly what you ask for, or an exception. No fallbacks.
 */

import { clear_cached_token, get_token, authenticate_with_tpm } from "./auth.js";
import { credentials_exist, load_credentials } from "./credentials.js";
import { enroll, type EnrollOptions } from "./enroll.js";
import { sign_challenge_with_private_key } from "./keys.js";
import {
  DEFAULT_KEY_ALGORITHM,
  HSMType,
  type Identity,
  KeyAlgorithm,
  type Token,
  TrustTier,
  this_token_has_not_yet_expired,
  format_authorization_header_value,
  format_identity_as_display_string,
} from "./identity.js";

// Re-export all exception classes
export {
  OneIDError,
  EnrollmentError,
  NoHSMError,
  UACDeniedError,
  HSMAccessError,
  AlreadyEnrolledError,
  HandleTakenError,
  HandleInvalidError,
  HandleRetiredError,
  AuthenticationError,
  NetworkError,
  NotEnrolledError,
  BinaryNotFoundError,
  RateLimitExceededError,
} from "./exceptions.js";

// Re-export types and enums
export {
  TrustTier,
  KeyAlgorithm,
  HSMType,
  DEFAULT_KEY_ALGORITHM,
  type Identity,
  type Token,
  type EnrollOptions,
  this_token_has_not_yet_expired,
  format_authorization_header_value,
  format_identity_as_display_string,
};

// Re-export core functions
export {
  enroll,
  get_token as getToken,
  get_token,
  clear_cached_token,
  authenticate_with_tpm,
  credentials_exist,
  sign_challenge_with_private_key,
};

/** SDK version string. */
export const VERSION = "0.1.0";

/**
 * Check the current enrolled identity.
 *
 * Reads the local credentials file and returns the identity information
 * stored during enrollment. Does NOT make a network request.
 *
 * @throws NotEnrolledError if no credentials exist.
 */
export function whoami(): Identity {
  const creds = load_credentials();

  // Resolve trust tier
  let trust_tier: TrustTier;
  const valid_tiers = Object.values(TrustTier) as string[];
  if (valid_tiers.includes(creds.trust_tier)) {
    trust_tier = creds.trust_tier as TrustTier;
  } else {
    trust_tier = TrustTier.DECLARED;
  }

  // Resolve key algorithm
  let key_algorithm: KeyAlgorithm;
  const valid_algorithms = Object.values(KeyAlgorithm) as string[];
  if (valid_algorithms.includes(creds.key_algorithm)) {
    key_algorithm = creds.key_algorithm as KeyAlgorithm;
  } else {
    key_algorithm = DEFAULT_KEY_ALGORITHM;
  }

  // Parse enrolled_at
  let enrolled_at: Date;
  try {
    enrolled_at = creds.enrolled_at ? new Date(creds.enrolled_at) : new Date();
  } catch {
    enrolled_at = new Date();
  }

  const internal_id = creds.client_id;
  const handle = internal_id.startsWith("@") ? internal_id : `@${internal_id}`;

  // Determine HSM type from credentials
  let hsm_type: HSMType | null = null;
  if (creds.private_key_pem != null) {
    hsm_type = HSMType.SOFTWARE;
  } else if (creds.hsm_key_reference != null) {
    hsm_type = HSMType.TPM;
  }

  return {
    internal_id,
    handle,
    trust_tier,
    hsm_type,
    hsm_manufacturer: null,
    enrolled_at,
    device_count: creds.hsm_key_reference ? 1 : 0,
    key_algorithm,
  };
}

/**
 * Force-refresh the cached OAuth2 token.
 *
 * Discards the in-memory cached token and fetches a new one
 * on the next getToken() call.
 */
export function refresh(): void {
  clear_cached_token();
}

// -- Default export for convenience --
const oneid = {
  enroll,
  getToken: get_token,
  get_token,
  whoami,
  refresh,
  credentials_exist,
  authenticate_with_tpm,
  sign_challenge_with_private_key,
  clear_cached_token,
  VERSION,
  TrustTier,
  KeyAlgorithm,
  HSMType,
  DEFAULT_KEY_ALGORITHM,
};

export default oneid;
