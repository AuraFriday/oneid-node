/**
 * Credential storage for the 1id.com Node.js SDK.
 *
 * Manages the local credentials file that stores OAuth2 client credentials
 * and the agent's signing key (for declared-tier software keys or references
 * to TPM/YubiKey keys for hardware-backed tiers).
 *
 * Storage locations:
 *   Windows:  %APPDATA%\oneid\credentials.json
 *   Linux:    ~/.config/oneid/credentials.json
 *   macOS:    ~/.config/oneid/credentials.json
 *
 * Security:
 *   - File permissions set to owner-only (0600 on Unix)
 *   - Private keys are stored PEM-encoded in the credentials file
 *   - Credentials are NEVER logged or printed
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { NotEnrolledError, OneIDError } from "./exceptions.js";

// -- Default server endpoints --
export const DEFAULT_API_BASE_URL = "https://1id.com";
export const DEFAULT_TOKEN_ENDPOINT = "https://1id.com/realms/agents/protocol/openid-connect/token";

// -- Credential file name --
const CREDENTIALS_FILENAME = "credentials.json";

/**
 * Credentials stored locally after enrollment.
 *
 * Contains everything needed to authenticate and sign challenges
 * without re-enrolling.
 */
export interface StoredCredentials {
  /** The 1id internal ID (e.g., '1id_a7b3c9d2'), used as OAuth2 client_id. */
  client_id: string;
  /** OAuth2 client secret issued by Keycloak. */
  client_secret: string;
  /** Full URL of the Keycloak token endpoint. */
  token_endpoint: string;
  /** Base URL for the 1id.com enrollment API. */
  api_base_url: string;
  /** The trust tier assigned at enrollment. */
  trust_tier: string;
  /** The key algorithm used for the signing key. */
  key_algorithm: string;
  /** PEM-encoded private key (declared tier). Null for TPM tiers. */
  private_key_pem?: string | null;
  /** Reference to the HSM-stored key (e.g., TPM AK handle). Null for declared tier. */
  hsm_key_reference?: string | null;
  /** ISO 8601 timestamp of enrollment. */
  enrolled_at?: string | null;
}

/**
 * Return the platform-appropriate directory for storing credentials.
 *
 * Windows:  %APPDATA%\oneid\
 * Linux:    ~/.config/oneid/
 * macOS:    ~/.config/oneid/
 */
export function get_credentials_directory(): string {
  const system_platform = os.platform();
  if (system_platform === "win32") {
    const appdata = process.env["APPDATA"];
    if (appdata) {
      return path.join(appdata, "oneid");
    }
    return path.join(os.homedir(), "AppData", "Roaming", "oneid");
  } else {
    const xdg_config_home = process.env["XDG_CONFIG_HOME"];
    if (xdg_config_home) {
      return path.join(xdg_config_home, "oneid");
    }
    return path.join(os.homedir(), ".config", "oneid");
  }
}

/**
 * Return the full path to the credentials JSON file.
 */
export function get_credentials_file_path(): string {
  return path.join(get_credentials_directory(), CREDENTIALS_FILENAME);
}

/**
 * Set file permissions to owner-only (0600 on Unix).
 * On Windows, %APPDATA% is already user-private by default.
 */
function set_owner_only_permissions(file_path: string): void {
  if (os.platform() !== "win32") {
    try {
      fs.chmodSync(file_path, 0o600);
    } catch {
      // Best effort -- may fail in some environments
    }
  }
}

/**
 * Save enrollment credentials to the local credentials file.
 *
 * Creates the directory if it doesn't exist. Sets file permissions
 * to owner-only for security.
 *
 * @returns Path to the saved credentials file.
 */
export function save_credentials(credentials: StoredCredentials): string {
  const credentials_directory = get_credentials_directory();
  fs.mkdirSync(credentials_directory, { recursive: true });

  const credentials_file_path = path.join(credentials_directory, CREDENTIALS_FILENAME);

  // Serialize to JSON -- only include key fields that are present
  const credentials_dict: Record<string, unknown> = {
    client_id: credentials.client_id,
    client_secret: credentials.client_secret,
    token_endpoint: credentials.token_endpoint,
    api_base_url: credentials.api_base_url,
    trust_tier: credentials.trust_tier,
    key_algorithm: credentials.key_algorithm,
    enrolled_at: credentials.enrolled_at ?? null,
  };

  if (credentials.private_key_pem != null) {
    credentials_dict["private_key_pem"] = credentials.private_key_pem;
  }
  if (credentials.hsm_key_reference != null) {
    credentials_dict["hsm_key_reference"] = credentials.hsm_key_reference;
  }

  fs.writeFileSync(credentials_file_path, JSON.stringify(credentials_dict, null, 2) + "\n", "utf-8");
  set_owner_only_permissions(credentials_file_path);

  return credentials_file_path;
}

/**
 * Load enrollment credentials from the local credentials file.
 *
 * @throws NotEnrolledError if no credentials file exists.
 * @throws OneIDError if the credentials file is corrupted.
 */
export function load_credentials(): StoredCredentials {
  const credentials_file_path = get_credentials_file_path();

  if (!fs.existsSync(credentials_file_path)) {
    throw new NotEnrolledError(
      `No credentials file found at ${credentials_file_path}. ` +
      "Call oneid.enroll() to create an identity first."
    );
  }

  let raw_json_text: string;
  let credentials_dict: Record<string, unknown>;

  try {
    raw_json_text = fs.readFileSync(credentials_file_path, "utf-8");
    credentials_dict = JSON.parse(raw_json_text);
  } catch (read_error) {
    throw new OneIDError(
      `Credentials file at ${credentials_file_path} is corrupted or unreadable: ${read_error}`,
      "CREDENTIALS_CORRUPTED"
    );
  }

  return {
    client_id: credentials_dict["client_id"] as string,
    client_secret: credentials_dict["client_secret"] as string,
    token_endpoint: credentials_dict["token_endpoint"] as string,
    api_base_url: credentials_dict["api_base_url"] as string,
    trust_tier: (credentials_dict["trust_tier"] as string) ?? "declared",
    key_algorithm: (credentials_dict["key_algorithm"] as string) ?? "ed25519",
    private_key_pem: (credentials_dict["private_key_pem"] as string) ?? null,
    hsm_key_reference: (credentials_dict["hsm_key_reference"] as string) ?? null,
    enrolled_at: (credentials_dict["enrolled_at"] as string) ?? null,
  };
}

/**
 * Check whether a credentials file exists (agent has enrolled).
 */
export function credentials_exist(): boolean {
  return fs.existsSync(get_credentials_file_path());
}

/**
 * Delete the local credentials file (for re-enrollment or cleanup).
 *
 * @returns true if the file was deleted, false if it didn't exist.
 */
export function delete_credentials(): boolean {
  const credentials_file_path = get_credentials_file_path();
  if (fs.existsSync(credentials_file_path)) {
    fs.unlinkSync(credentials_file_path);
    return true;
  }
  return false;
}
