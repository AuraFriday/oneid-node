/**
 * Go binary helper for the 1id.com Node.js SDK.
 *
 * Manages the oneid-enroll Go binary:
 * - Locates the binary (cached or PATH)
 * - Downloads it from GitHub releases if not present
 * - Spawns it for HSM operations (detect, extract, activate, sign)
 * - Parses JSON output
 *
 * The binary handles all platform-specific HSM operations:
 * - TPM access (Windows TBS.dll, Linux /dev/tpm*)
 * - YubiKey/PIV access (PCSC)
 * - Privilege elevation (UAC, sudo, pkexec)
 */

import * as child_process from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as https from "node:https";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

import {
  BinaryNotFoundError,
  HSMAccessError,
  NoHSMError,
  UACDeniedError,
} from "./exceptions.js";

// -- GitHub release URL for auto-download --
const GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE =
  "https://github.com/AuraFriday/oneid-enroll/releases/latest/download/{binary_name}";

// -- Binary naming convention --
const BINARY_NAME_PREFIX = "oneid-enroll";

/**
 * Return the platform-specific binary filename.
 */
function get_platform_binary_name(): string {
  const system = os.platform();
  let machine = os.arch();

  // Normalize architecture names
  if (machine === "x64") { machine = "amd64"; }
  else if (machine === "arm64") { /* already correct */ }

  if (system === "win32") {
    return `${BINARY_NAME_PREFIX}-windows-${machine}.exe`;
  } else if (system === "darwin") {
    return `${BINARY_NAME_PREFIX}-darwin-${machine}`;
  } else {
    return `${BINARY_NAME_PREFIX}-linux-${machine}`;
  }
}

/**
 * Return the directory where downloaded binaries are cached.
 */
function get_binary_cache_directory(): string {
  if (os.platform() === "win32") {
    const base = process.env["APPDATA"] ?? path.join(os.homedir(), "AppData", "Roaming");
    return path.join(base, "oneid", "bin");
  } else {
    return path.join(os.homedir(), ".local", "share", "oneid", "bin");
  }
}

/**
 * Check if a file exists and is executable.
 */
function file_exists_and_is_executable(file_path: string): boolean {
  try {
    fs.accessSync(file_path, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Locate the oneid-enroll binary.
 *
 * Search order:
 * 1. Binary cache directory (~/.local/share/oneid/bin/ or %APPDATA%/oneid/bin/)
 * 2. Current working directory
 * 3. System PATH
 *
 * @returns Path to the binary if found, null otherwise.
 */
export function find_binary(): string | null {
  const binary_name = get_platform_binary_name();

  // 1. Check cache directory
  const cache_dir = get_binary_cache_directory();
  const cached_binary_path = path.join(cache_dir, binary_name);
  if (file_exists_and_is_executable(cached_binary_path)) {
    return cached_binary_path;
  }

  // 2. Check current working directory
  const local_binary_path = path.join(process.cwd(), binary_name);
  if (file_exists_and_is_executable(local_binary_path)) {
    return local_binary_path;
  }

  // Also check generic name
  const generic_name = os.platform() === "win32" ? `${BINARY_NAME_PREFIX}.exe` : BINARY_NAME_PREFIX;
  const local_generic_path = path.join(process.cwd(), generic_name);
  if (file_exists_and_is_executable(local_generic_path)) {
    return local_generic_path;
  }

  // 3. Check PATH
  const which_command = os.platform() === "win32" ? "where" : "which";
  for (const name_to_search of [binary_name, generic_name]) {
    try {
      const result = child_process.execSync(`${which_command} ${name_to_search}`, {
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      });
      const found_path = result.trim().split("\n")[0]?.trim();
      if (found_path && fs.existsSync(found_path)) {
        return found_path;
      }
    } catch {
      // Not found in PATH
    }
  }

  return null;
}

/**
 * Download a file from a URL to a local path. Follows redirects (up to 5).
 */
function download_file_to_path(url: string, destination: string, max_redirects: number = 5): Promise<void> {
  return new Promise((resolve, reject) => {
    if (max_redirects <= 0) {
      reject(new BinaryNotFoundError("Too many redirects while downloading binary"));
      return;
    }

    const transport = url.startsWith("https:") ? https : http;
    transport.get(url, { headers: { "User-Agent": "oneid-sdk-node/0.1.0" } }, (res) => {
      // Handle redirects (GitHub releases redirect to S3)
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        download_file_to_path(res.headers.location, destination, max_redirects - 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        reject(new BinaryNotFoundError(
          `Failed to download from ${url}: HTTP ${res.statusCode}`
        ));
        return;
      }

      const file_stream = fs.createWriteStream(destination);
      res.pipe(file_stream);
      file_stream.on("finish", () => {
        file_stream.close();
        resolve();
      });
      file_stream.on("error", (err) => {
        reject(new BinaryNotFoundError(`Failed to write binary to ${destination}: ${err.message}`));
      });
    }).on("error", (err) => {
      reject(new BinaryNotFoundError(`Failed to download from ${url}: ${err.message}`));
    });
  });
}

/**
 * Download the content of a URL as a string. Follows redirects.
 */
function download_text_from_url(url: string, max_redirects: number = 5): Promise<string> {
  return new Promise((resolve, reject) => {
    if (max_redirects <= 0) {
      reject(new Error("Too many redirects"));
      return;
    }

    const transport = url.startsWith("https:") ? https : http;
    transport.get(url, { headers: { "User-Agent": "oneid-sdk-node/0.1.0" } }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        download_text_from_url(res.headers.location, max_redirects - 1)
          .then(resolve)
          .catch(reject);
        return;
      }

      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }

      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => { chunks.push(chunk); });
      res.on("end", () => { resolve(Buffer.concat(chunks).toString("utf-8")); });
    }).on("error", reject);
  });
}

/**
 * Download the oneid-enroll binary from the GitHub 'latest' release.
 *
 * Downloads to a temporary file first, verifies the SHA-256 checksum,
 * then moves to the final location.
 */
async function download_binary_from_github_release(
  binary_name: string,
  destination_path: string,
): Promise<string> {
  const binary_download_url = GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE.replace("{binary_name}", binary_name);
  const checksum_download_url = GITHUB_RELEASE_DOWNLOAD_URL_TEMPLATE.replace("{binary_name}", binary_name + ".sha256");

  const destination_dir = path.dirname(destination_path);
  fs.mkdirSync(destination_dir, { recursive: true });

  // Use a temp file for atomic download
  const temp_file_path = path.join(destination_dir, `oneid-enroll-download-${Date.now()}.tmp`);

  try {
    // Step 1: Download binary
    await download_file_to_path(binary_download_url, temp_file_path);
    const downloaded_size = fs.statSync(temp_file_path).size;

    if (downloaded_size < 100_000) {
      throw new BinaryNotFoundError(
        `Downloaded binary is suspiciously small (${downloaded_size} bytes). ` +
        "The download URL may be incorrect or the release may be empty."
      );
    }

    // Step 2: Verify SHA-256 checksum
    try {
      const checksum_text = await download_text_from_url(checksum_download_url);
      const expected_sha256_hash = checksum_text.trim().split(/\s+/)[0]?.toLowerCase();

      const file_buffer = fs.readFileSync(temp_file_path);
      const actual_sha256_hash = crypto.createHash("sha256").update(file_buffer).digest("hex").toLowerCase();

      if (actual_sha256_hash !== expected_sha256_hash) {
        throw new BinaryNotFoundError(
          `SHA-256 checksum mismatch for ${binary_name}. ` +
          `Expected: ${expected_sha256_hash}, got: ${actual_sha256_hash}. ` +
          "The binary may have been tampered with or the download was corrupted."
        );
      }
    } catch (checksum_error) {
      if (checksum_error instanceof BinaryNotFoundError) { throw checksum_error; }
      // Checksum download failed -- proceed without verification (warn)
      console.warn(
        `[oneid] Could not download checksum file (${checksum_error}). ` +
        "Proceeding without verification."
      );
    }

    // Step 3: Move temp file to final destination
    if (fs.existsSync(destination_path)) {
      fs.unlinkSync(destination_path);
    }
    fs.renameSync(temp_file_path, destination_path);

    // Step 4: Set executable permission on non-Windows
    if (os.platform() !== "win32") {
      fs.chmodSync(destination_path, 0o755);
    }

    return destination_path;
  } finally {
    // Clean up temp file on failure
    try {
      if (fs.existsSync(temp_file_path)) { fs.unlinkSync(temp_file_path); }
    } catch { /* best effort */ }
  }
}

/**
 * Ensure the oneid-enroll binary is available, downloading if needed.
 *
 * @returns Path to the available binary.
 * @throws BinaryNotFoundError if the binary cannot be found or downloaded.
 */
export async function ensure_binary_available(): Promise<string> {
  const found_binary_path = find_binary();
  if (found_binary_path != null) {
    return found_binary_path;
  }

  // Binary not found locally -- attempt auto-download
  const binary_name = get_platform_binary_name();
  const cache_dir = get_binary_cache_directory();
  const destination = path.join(cache_dir, binary_name);

  try {
    return await download_binary_from_github_release(binary_name, destination);
  } catch (download_error) {
    throw new BinaryNotFoundError(
      `oneid-enroll binary not found in cache, current directory, or PATH, ` +
      `and auto-download failed: ${download_error}. ` +
      `Expected filename: ${binary_name}. ` +
      `Manual download: https://github.com/AuraFriday/oneid-enroll/releases/latest`
    );
  }
}

/**
 * Run an oneid-enroll subcommand and parse its JSON output.
 */
export async function run_binary_command(
  command: string,
  args?: string[],
  json_mode: boolean = true,
  timeout_milliseconds: number = 30_000,
): Promise<Record<string, unknown>> {
  const binary_path = await ensure_binary_available();

  const cmd_args = [command];
  if (json_mode) { cmd_args.push("--json"); }
  if (args) { cmd_args.push(...args); }

  return new Promise((resolve, reject) => {
    let stdout_data = "";
    let stderr_data = "";

    const spawned_process = child_process.spawn(binary_path, cmd_args, {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: timeout_milliseconds,
    });

    spawned_process.stdout?.on("data", (chunk: Buffer) => { stdout_data += chunk.toString(); });
    spawned_process.stderr?.on("data", (chunk: Buffer) => { stderr_data += chunk.toString(); });

    spawned_process.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(new BinaryNotFoundError(`Could not execute ${binary_path}: file not found`));
      } else if ((err as NodeJS.ErrnoException).code === "EACCES") {
        reject(new BinaryNotFoundError(`Could not execute ${binary_path}: permission denied`));
      } else {
        reject(new HSMAccessError(`Error spawning ${binary_path}: ${err.message}`));
      }
    });

    spawned_process.on("close", (exit_code) => {
      let output: Record<string, unknown>;

      if (json_mode && stdout_data.trim()) {
        try {
          output = JSON.parse(stdout_data.trim());
        } catch {
          reject(new HSMAccessError(
            `oneid-enroll returned invalid JSON: ${stdout_data.slice(0, 500)}`
          ));
          return;
        }
      } else {
        output = { stdout: stdout_data, stderr: stderr_data, returncode: exit_code };
      }

      if (exit_code !== 0) {
        const error_code = (output.error_code as string) ?? "UNKNOWN";
        const error_message = (output.error as string) ?? (stderr_data.trim() || `Exit code ${exit_code}`);

        if (error_code === "NO_HSM_FOUND" || /no.*hsm/i.test(error_message) || /no.*tpm/i.test(error_message)) {
          reject(new NoHSMError(error_message));
        } else if (error_code === "UAC_DENIED" || /denied/i.test(error_message)) {
          reject(new UACDeniedError(error_message));
        } else if (error_code === "HSM_ACCESS_ERROR") {
          reject(new HSMAccessError(error_message));
        } else {
          reject(new HSMAccessError(`oneid-enroll '${command}' failed: ${error_message}`));
        }
        return;
      }

      resolve(output);
    });
  });
}

/**
 * Detect available hardware security modules via the Go binary.
 *
 * Runs 'oneid-enroll detect --json' which does NOT require elevation.
 */
export async function detect_available_hsms(): Promise<Record<string, unknown>[]> {
  try {
    const output = await run_binary_command("detect");
    return (output.hsms as Record<string, unknown>[]) ?? [];
  } catch (error) {
    if (error instanceof NoHSMError) { return []; }
    if (error instanceof BinaryNotFoundError) { throw error; }
    return [];
  }
}

/**
 * Extract attestation data from an HSM (requires elevation).
 */
export async function extract_attestation_data(
  hsm: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const hsm_type = (hsm.type as string) ?? "tpm";
  return run_binary_command("extract", ["--type", hsm_type, "--elevated"]);
}

/**
 * Decrypt a credential activation challenge via the HSM (requires elevation).
 */
export async function activate_credential(
  _hsm: Record<string, unknown>,
  credential_blob_b64: string,
  encrypted_secret_b64: string,
  ak_handle: string,
): Promise<string> {
  const output = await run_binary_command("activate", [
    "--credential-blob", credential_blob_b64,
    "--encrypted-secret", encrypted_secret_b64,
    "--ak-handle", ak_handle,
    "--elevated",
  ]);
  return (output.decrypted_credential as string) ?? "";
}

/**
 * Sign a challenge nonce using the TPM AK -- NO ELEVATION NEEDED.
 *
 * This is the core of ongoing TPM-backed authentication.
 */
export async function sign_challenge_with_tpm(
  nonce_b64: string,
  ak_handle: string,
): Promise<Record<string, unknown>> {
  return run_binary_command("sign", [
    "--nonce", nonce_b64,
    "--ak-handle", ak_handle,
  ]);
}
