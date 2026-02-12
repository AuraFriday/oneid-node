/**
 * Enrollment logic for the 1id.com Node.js SDK.
 *
 * Orchestrates the enrollment flow for all trust tiers:
 * - Declared: Pure software, generates a keypair, sends public key to server.
 * - Sovereign: Spawns Go binary for TPM operations, two-phase enrollment.
 * - Sovereign-portable: Spawns Go binary for YubiKey/PIV operations.
 *
 * CRITICAL DESIGN RULE: requestTier is a REQUIREMENT, not a preference.
 * The agent gets exactly the tier it requests, or an exception.
 * There are NO automatic fallbacks. The caller's logic decides what to do.
 */

import { OneIDAPIClient } from "./client.js";
import {
  DEFAULT_API_BASE_URL,
  type StoredCredentials,
  save_credentials,
} from "./credentials.js";
import { EnrollmentError, NoHSMError } from "./exceptions.js";
import {
  DEFAULT_KEY_ALGORITHM,
  HSMType,
  type Identity,
  KeyAlgorithm,
  TrustTier,
} from "./identity.js";
import { generate_keypair } from "./keys.js";

/** Trust tiers that require an HSM and the Go binary. */
const TIERS_REQUIRING_HSM: ReadonlySet<TrustTier> = new Set([
  TrustTier.SOVEREIGN,
  TrustTier.SOVEREIGN_PORTABLE,
  TrustTier.LEGACY,
  TrustTier.VIRTUAL,
  TrustTier.ENCLAVE,
]);

/** HSM type preferences by tier. */
const TIER_TO_HSM_TYPE_PREFERENCES: Readonly<Record<string, string[]>> = {
  [TrustTier.SOVEREIGN]: ["tpm"],
  [TrustTier.SOVEREIGN_PORTABLE]: ["yubikey", "nitrokey", "feitian", "solokeys"],
  [TrustTier.LEGACY]: ["tpm", "yubikey", "nitrokey", "feitian"],
  [TrustTier.VIRTUAL]: ["tpm"],
  [TrustTier.ENCLAVE]: ["secure_enclave"],
};

/**
 * Options for the enroll() function.
 */
export interface EnrollOptions {
  /** REQUIRED. The trust tier to request. */
  request_tier: string;
  /** Optional. Human contact email for this agent. */
  operator_email?: string | null;
  /** Optional. Vanity handle to claim (without '@' prefix). */
  requested_handle?: string | null;
  /** Optional. Key algorithm for declared-tier enrollment. Default: 'ed25519'. */
  key_algorithm?: string | KeyAlgorithm | null;
  /** Optional. Override the API base URL (for testing/staging). */
  api_base_url?: string;
}

/**
 * Enroll this agent with 1id.com to receive a unique, verifiable identity.
 *
 * This is the primary entry point for enrollment. The agent specifies
 * which trust tier it requires, and gets exactly that tier or an exception.
 *
 * THERE ARE NO AUTOMATIC FALLBACKS.
 *
 * @param options Enrollment options including the required request_tier.
 * @returns The enrolled Identity.
 * @throws NoHSMError if requested tier requires an HSM but none was found.
 * @throws EnrollmentError for any enrollment failure.
 * @throws NetworkError if the server cannot be reached.
 */
export async function enroll(options: EnrollOptions): Promise<Identity> {
  // Validate and normalize the requested tier
  const valid_tiers = Object.values(TrustTier) as string[];
  if (!valid_tiers.includes(options.request_tier)) {
    throw new EnrollmentError(
      `Invalid trust tier: '${options.request_tier}'. Valid tiers: ${valid_tiers.join(", ")}`
    );
  }
  const tier = options.request_tier as TrustTier;

  // Normalize key algorithm
  let resolved_key_algorithm: KeyAlgorithm;
  if (options.key_algorithm == null) {
    resolved_key_algorithm = DEFAULT_KEY_ALGORITHM;
  } else if (typeof options.key_algorithm === "string") {
    const valid_algorithms = Object.values(KeyAlgorithm) as string[];
    if (!valid_algorithms.includes(options.key_algorithm)) {
      throw new EnrollmentError(
        `Invalid key algorithm: '${options.key_algorithm}'. Valid: ${valid_algorithms.join(", ")}`
      );
    }
    resolved_key_algorithm = options.key_algorithm as KeyAlgorithm;
  } else {
    resolved_key_algorithm = options.key_algorithm;
  }

  const api_base_url = options.api_base_url ?? DEFAULT_API_BASE_URL;

  // Route to the appropriate enrollment flow
  if (tier === TrustTier.DECLARED) {
    return enroll_declared_tier(
      options.operator_email ?? null,
      options.requested_handle ?? null,
      resolved_key_algorithm,
      api_base_url,
    );
  } else if (TIERS_REQUIRING_HSM.has(tier)) {
    return enroll_hsm_tier(
      tier,
      options.operator_email ?? null,
      options.requested_handle ?? null,
      api_base_url,
    );
  } else {
    throw new EnrollmentError(`Tier '${tier}' is not yet implemented`);
  }
}

/**
 * Enroll at the declared trust tier (software keys, no HSM).
 */
async function enroll_declared_tier(
  operator_email: string | null,
  requested_handle: string | null,
  key_algorithm: KeyAlgorithm,
  api_base_url: string,
): Promise<Identity> {
  // Step 1: Generate keypair
  const { private_key_pem, public_key_pem } = generate_keypair(key_algorithm);

  // Step 2: Send enrollment request to server
  const api_client = new OneIDAPIClient(api_base_url);
  const server_response = await api_client.enroll_declared(
    public_key_pem,
    key_algorithm,
    operator_email,
    requested_handle,
  );

  // Step 3: Parse server response
  const identity_data = (server_response.identity ?? {}) as Record<string, unknown>;
  const credentials_data = (server_response.credentials ?? {}) as Record<string, unknown>;

  const internal_id = (identity_data.internal_id as string) ?? "";
  const handle = (identity_data.handle as string) ?? `@${internal_id.slice(0, 12)}`;
  const enrolled_at_str = (identity_data.registered_at as string) ?? new Date().toISOString();

  // Step 4: Store credentials locally
  const stored_credentials: StoredCredentials = {
    client_id: (credentials_data.client_id as string) ?? internal_id,
    client_secret: (credentials_data.client_secret as string) ?? "",
    token_endpoint: (credentials_data.token_endpoint as string) ??
      `${api_base_url}/realms/agents/protocol/openid-connect/token`,
    api_base_url,
    trust_tier: TrustTier.DECLARED,
    key_algorithm,
    private_key_pem,
    enrolled_at: enrolled_at_str,
  };
  const credentials_file_path = save_credentials(stored_credentials);
  console.log(`[oneid] Credentials saved to ${credentials_file_path}`);

  // Step 5: Return Identity object
  let enrolled_at: Date;
  try {
    enrolled_at = new Date(enrolled_at_str);
  } catch {
    enrolled_at = new Date();
  }

  return {
    internal_id,
    handle,
    trust_tier: TrustTier.DECLARED,
    hsm_type: HSMType.SOFTWARE,
    hsm_manufacturer: null,
    enrolled_at,
    device_count: 0,
    key_algorithm,
  };
}

/**
 * Enroll at an HSM-backed trust tier (sovereign, sovereign-portable, etc.).
 */
async function enroll_hsm_tier(
  request_tier: TrustTier,
  operator_email: string | null,
  requested_handle: string | null,
  api_base_url: string,
): Promise<Identity> {
  const {
    detect_available_hsms,
    extract_attestation_data,
    activate_credential,
  } = await import("./helper.js");

  // Step 1: Detect HSMs via Go binary
  const detected_hsms = await detect_available_hsms();

  if (detected_hsms.length === 0) {
    throw new NoHSMError(
      `No hardware security module found. ` +
      `The '${request_tier}' tier requires a TPM, YubiKey, or similar device.`
    );
  }

  // Step 2: Select the appropriate HSM
  const selected_hsm = select_hsm_for_tier(detected_hsms, request_tier);
  if (selected_hsm == null) {
    const hsm_types = detected_hsms.map(h => (h.type as string) ?? "unknown").join(", ");
    throw new NoHSMError(
      `Found HSM(s) (${hsm_types}) but none are compatible with the '${request_tier}' tier.`
    );
  }

  // Step 3: Extract attestation (requires elevation)
  const attestation_data = await extract_attestation_data(selected_hsm);

  // Step 4: Begin enrollment with server
  const api_client = new OneIDAPIClient(api_base_url);
  const begin_response = await api_client.enroll_begin(
    attestation_data.ek_cert_pem as string,
    (attestation_data.ak_public_pem as string) ?? "",
    (attestation_data.ak_tpmt_public_b64 as string) ?? "",
    (attestation_data.ek_public_pem as string) ?? "",
    (attestation_data.chain_pem as string[]) ?? undefined,
    (selected_hsm.type as string) ?? "tpm",
    operator_email,
    requested_handle,
  );

  // Step 5: Activate credential via TPM (requires elevation)
  const decrypted_credential = await activate_credential(
    selected_hsm,
    begin_response.credential_blob as string,
    begin_response.encrypted_secret as string,
    (attestation_data.ak_handle as string) ?? "0x81000100",
  );

  // Step 6: Complete enrollment with server
  const activate_response = await api_client.enroll_activate(
    begin_response.enrollment_session_id as string,
    decrypted_credential,
  );

  // Step 7: Store credentials and return Identity
  const identity_data = (activate_response.identity ?? {}) as Record<string, unknown>;
  const credentials_data = (activate_response.credentials ?? {}) as Record<string, unknown>;

  const internal_id = (identity_data.internal_id as string) ?? "";
  const handle = (identity_data.handle as string) ?? `@${internal_id.slice(0, 12)}`;
  const trust_tier_str = (identity_data.trust_tier as string) ?? request_tier;
  const enrolled_at_str = (identity_data.registered_at as string) ?? new Date().toISOString();

  const stored_credentials: StoredCredentials = {
    client_id: (credentials_data.client_id as string) ?? internal_id,
    client_secret: (credentials_data.client_secret as string) ?? "",
    token_endpoint: (credentials_data.token_endpoint as string) ??
      `${api_base_url}/realms/agents/protocol/openid-connect/token`,
    api_base_url,
    trust_tier: trust_tier_str,
    key_algorithm: "tpm-ak",
    hsm_key_reference: (attestation_data.ak_handle as string) ?? null,
    enrolled_at: enrolled_at_str,
  };
  save_credentials(stored_credentials);

  let enrolled_at: Date;
  try {
    enrolled_at = new Date(enrolled_at_str);
  } catch {
    enrolled_at = new Date();
  }

  // Resolve trust tier enum
  let trust_tier: TrustTier;
  const valid_tiers = Object.values(TrustTier) as string[];
  if (valid_tiers.includes(trust_tier_str)) {
    trust_tier = trust_tier_str as TrustTier;
  } else {
    trust_tier = request_tier;
  }

  // Resolve HSM type enum
  let hsm_type: HSMType;
  const hsm_type_str = (selected_hsm.type as string) ?? "tpm";
  const valid_hsm_types = Object.values(HSMType) as string[];
  if (valid_hsm_types.includes(hsm_type_str)) {
    hsm_type = hsm_type_str as HSMType;
  } else {
    hsm_type = HSMType.TPM;
  }

  return {
    internal_id,
    handle,
    trust_tier,
    hsm_type,
    hsm_manufacturer: (selected_hsm.manufacturer as string) ?? null,
    enrolled_at,
    device_count: (identity_data.device_count as number) ?? 1,
    key_algorithm: KeyAlgorithm.RSA_2048,
  };
}

/**
 * Select the best matching HSM for the requested tier.
 */
function select_hsm_for_tier(
  detected_hsms: Record<string, unknown>[],
  request_tier: TrustTier,
): Record<string, unknown> | null {
  const preferred_types = TIER_TO_HSM_TYPE_PREFERENCES[request_tier] ?? [];

  for (const preferred_type of preferred_types) {
    for (const hsm of detected_hsms) {
      if (hsm.type === preferred_type) {
        return hsm;
      }
    }
  }

  return null;
}
