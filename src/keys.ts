/**
 * Cryptographic key generation for the 1id.com Node.js SDK.
 *
 * Uses Node.js built-in `crypto` module -- zero external dependencies.
 *
 * Supports multiple key algorithms for declared-tier software keys:
 *   - Ed25519:     128-bit security, smallest keys, fastest. Default.
 *   - ECDSA P-256: 128-bit security, widely compatible (NIST curve).
 *   - ECDSA P-384: 192-bit security, higher security NIST curve.
 *   - RSA-2048:    112-bit security, legacy compatibility.
 *   - RSA-4096:    128-bit security, higher security RSA.
 *
 * For TPM tiers, key generation happens inside the TPM hardware via
 * the Go binary. This module is only used for declared-tier enrollment.
 */

import * as crypto from "node:crypto";
import { KeyAlgorithm } from "./identity.js";

/**
 * A generated keypair: private key PEM + public key PEM.
 */
export interface GeneratedKeypair {
  /** PEM-encoded PKCS#8 private key. */
  private_key_pem: string;
  /** PEM-encoded SPKI public key. */
  public_key_pem: string;
}

/**
 * Generate a new keypair for declared-tier enrollment.
 *
 * The private key is stored locally in the credentials file. The public
 * key is sent to the 1id.com server during enrollment. The private key
 * is used later for challenge-response signing by relying parties.
 *
 * @param algorithm Which key algorithm to use. Default: Ed25519.
 * @returns The generated keypair as PEM strings.
 * @throws Error if the algorithm is not supported.
 */
export function generate_keypair(algorithm: KeyAlgorithm = KeyAlgorithm.ED25519): GeneratedKeypair {
  let key_pair: crypto.KeyPairKeyObjectResult;

  if (algorithm === KeyAlgorithm.ED25519) {
    key_pair = crypto.generateKeyPairSync("ed25519");
  } else if (algorithm === KeyAlgorithm.ECDSA_P256) {
    key_pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  } else if (algorithm === KeyAlgorithm.ECDSA_P384) {
    key_pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
  } else if (algorithm === KeyAlgorithm.RSA_2048) {
    key_pair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 65537,
    });
  } else if (algorithm === KeyAlgorithm.RSA_4096) {
    key_pair = crypto.generateKeyPairSync("rsa", {
      modulusLength: 4096,
      publicExponent: 65537,
    });
  } else {
    const valid_algorithms = Object.values(KeyAlgorithm).join(", ");
    throw new Error(
      `Unsupported key algorithm: ${algorithm}. Supported: ${valid_algorithms}`
    );
  }

  const private_key_pem = key_pair.privateKey.export({
    type: "pkcs8",
    format: "pem",
  }) as string;

  const public_key_pem = key_pair.publicKey.export({
    type: "spki",
    format: "pem",
  }) as string;

  return { private_key_pem, public_key_pem };
}

/**
 * Sign a challenge nonce using the stored private key.
 *
 * Used for relying-party live re-verification: the relying party
 * sends a nonce via 1id.com, the SDK signs it with the agent's
 * private key, and 1id.com verifies the signature against the
 * stored public key.
 *
 * The signing algorithm is determined automatically from the key type:
 * - Ed25519: EdDSA (no hash selection needed)
 * - ECDSA: SHA-256 (P-256) or SHA-384 (P-384)
 * - RSA: SHA-256 with PKCS1v15
 *
 * @param private_key_pem PEM-encoded private key.
 * @param challenge_bytes The raw bytes of the challenge nonce to sign.
 * @returns The signature as a Buffer.
 */
export function sign_challenge_with_private_key(
  private_key_pem: string,
  challenge_bytes: Buffer,
): Buffer {
  const private_key_object = crypto.createPrivateKey(private_key_pem);
  const key_type = private_key_object.asymmetricKeyType;

  if (key_type === "ed25519") {
    return crypto.sign(null, challenge_bytes, private_key_object);
  } else if (key_type === "ec") {
    // Determine hash from curve: P-384 uses SHA-384, others use SHA-256
    const key_details = private_key_object.asymmetricKeyDetails;
    const hash_algorithm = key_details?.namedCurve === "P-384" ? "sha384" : "sha256";
    return crypto.sign(hash_algorithm, challenge_bytes, private_key_object);
  } else if (key_type === "rsa") {
    return crypto.sign("sha256", challenge_bytes, {
      key: private_key_object,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    });
  } else {
    throw new Error(`Unsupported key type for signing: ${key_type}`);
  }
}
