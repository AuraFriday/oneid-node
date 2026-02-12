/**
 * Integration and unit tests for the 1id.com Node.js SDK.
 *
 * Tests include:
 * 1. Offline tests (key generation, credential storage, whoami, error hierarchy)
 * 2. Live enrollment test against 1id.com (may fail if server is down)
 *
 * Run with: node --test dist/test/test_declared_enrollment.js
 */

import { describe, it, before, after } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as crypto from "node:crypto";

import {
  enroll,
  whoami,
  credentials_exist,
  TrustTier,
  KeyAlgorithm,
  HSMType,
  VERSION,
  OneIDError,
  EnrollmentError,
  NoHSMError,
  NetworkError,
  NotEnrolledError,
  sign_challenge_with_private_key,
} from "../index.js";
import {
  get_credentials_file_path,
  delete_credentials,
  save_credentials,
  load_credentials,
  type StoredCredentials,
} from "../credentials.js";
import { generate_keypair } from "../keys.js";

// -- Test configuration --
const BACKUP_SUFFIX = ".test-backup";

// =====================================================================
// OFFLINE UNIT TESTS (no network required)
// =====================================================================

describe("Key generation (offline)", () => {
  it("should generate Ed25519 keypair", () => {
    const kp = generate_keypair(KeyAlgorithm.ED25519);
    assert.ok(kp.private_key_pem.includes("BEGIN PRIVATE KEY"), "should contain PEM private key header");
    assert.ok(kp.public_key_pem.includes("BEGIN PUBLIC KEY"), "should contain PEM public key header");
  });

  it("should generate ECDSA P-256 keypair", () => {
    const kp = generate_keypair(KeyAlgorithm.ECDSA_P256);
    assert.ok(kp.private_key_pem.includes("BEGIN PRIVATE KEY"));
    assert.ok(kp.public_key_pem.includes("BEGIN PUBLIC KEY"));
  });

  it("should generate ECDSA P-384 keypair", () => {
    const kp = generate_keypair(KeyAlgorithm.ECDSA_P384);
    assert.ok(kp.private_key_pem.includes("BEGIN PRIVATE KEY"));
    assert.ok(kp.public_key_pem.includes("BEGIN PUBLIC KEY"));
  });

  it("should generate RSA-2048 keypair", () => {
    const kp = generate_keypair(KeyAlgorithm.RSA_2048);
    assert.ok(kp.private_key_pem.includes("BEGIN PRIVATE KEY"));
    assert.ok(kp.public_key_pem.includes("BEGIN PUBLIC KEY"));
  });

  it("should generate RSA-4096 keypair", () => {
    const kp = generate_keypair(KeyAlgorithm.RSA_4096);
    assert.ok(kp.private_key_pem.includes("BEGIN PRIVATE KEY"));
    assert.ok(kp.public_key_pem.includes("BEGIN PUBLIC KEY"));
  });
});

describe("Challenge signing (offline)", () => {
  it("should sign and verify with Ed25519", () => {
    const kp = generate_keypair(KeyAlgorithm.ED25519);
    const challenge = crypto.randomBytes(32);
    const signature = sign_challenge_with_private_key(kp.private_key_pem, challenge);
    assert.ok(signature.length > 0, "signature should be non-empty");

    // Verify the signature using Node.js crypto
    const public_key = crypto.createPublicKey(kp.public_key_pem);
    const is_valid = crypto.verify(null, challenge, public_key, signature);
    assert.ok(is_valid, "Ed25519 signature should verify correctly");
  });

  it("should sign and verify with ECDSA P-256", () => {
    const kp = generate_keypair(KeyAlgorithm.ECDSA_P256);
    const challenge = crypto.randomBytes(32);
    const signature = sign_challenge_with_private_key(kp.private_key_pem, challenge);
    assert.ok(signature.length > 0);

    const public_key = crypto.createPublicKey(kp.public_key_pem);
    const is_valid = crypto.verify("sha256", challenge, public_key, signature);
    assert.ok(is_valid, "ECDSA P-256 signature should verify correctly");
  });

  it("should sign and verify with RSA-2048", () => {
    const kp = generate_keypair(KeyAlgorithm.RSA_2048);
    const challenge = crypto.randomBytes(32);
    const signature = sign_challenge_with_private_key(kp.private_key_pem, challenge);
    assert.ok(signature.length > 0);

    const public_key = crypto.createPublicKey(kp.public_key_pem);
    const is_valid = crypto.verify("sha256", challenge, {
      key: public_key,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }, signature);
    assert.ok(is_valid, "RSA-2048 signature should verify correctly");
  });
});

describe("Credential storage (offline)", () => {
  const credentials_file_path = get_credentials_file_path();
  const backup_path = credentials_file_path + ".unit-test-backup";
  let had_existing_credentials = false;

  before(() => {
    if (fs.existsSync(credentials_file_path)) {
      fs.copyFileSync(credentials_file_path, backup_path);
      had_existing_credentials = true;
      fs.unlinkSync(credentials_file_path);
    }
  });

  after(() => {
    // Restore original credentials
    if (had_existing_credentials && fs.existsSync(backup_path)) {
      if (fs.existsSync(credentials_file_path)) {
        fs.unlinkSync(credentials_file_path);
      }
      fs.renameSync(backup_path, credentials_file_path);
    } else if (fs.existsSync(credentials_file_path)) {
      // Clean up test credentials
      fs.unlinkSync(credentials_file_path);
    }
  });

  it("should save and load credentials", () => {
    const test_credentials: StoredCredentials = {
      client_id: "1id_test1234",
      client_secret: "secret_abc123",
      token_endpoint: "https://1id.com/realms/agents/protocol/openid-connect/token",
      api_base_url: "https://1id.com",
      trust_tier: "declared",
      key_algorithm: "ed25519",
      private_key_pem: "-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----",
      enrolled_at: "2026-02-11T00:00:00Z",
    };

    save_credentials(test_credentials);
    assert.ok(credentials_exist(), "credentials should exist after save");

    const loaded = load_credentials();
    assert.equal(loaded.client_id, "1id_test1234");
    assert.equal(loaded.client_secret, "secret_abc123");
    assert.equal(loaded.trust_tier, "declared");
    assert.equal(loaded.key_algorithm, "ed25519");
    assert.ok(loaded.private_key_pem?.includes("TEST"));
  });

  it("should handle whoami() with saved credentials", () => {
    // Credentials from previous test should still exist
    const identity = whoami();
    assert.equal(identity.internal_id, "1id_test1234");
    assert.equal(identity.handle, "@1id_test1234");
    assert.equal(identity.trust_tier, TrustTier.DECLARED);
    assert.equal(identity.hsm_type, HSMType.SOFTWARE);
    assert.equal(identity.key_algorithm, KeyAlgorithm.ED25519);
  });

  it("should throw NotEnrolledError when no credentials exist", () => {
    delete_credentials();
    assert.throws(
      () => whoami(),
      (error: Error) => {
        assert.ok(error instanceof NotEnrolledError);
        return true;
      },
    );
  });
});

describe("Exception hierarchy (offline)", () => {
  it("should have correct inheritance chain", () => {
    const enrollment_error = new EnrollmentError("test");
    assert.ok(enrollment_error instanceof OneIDError, "EnrollmentError should extend OneIDError");
    assert.ok(enrollment_error instanceof Error, "EnrollmentError should extend Error");

    const no_hsm_error = new NoHSMError("test");
    assert.ok(no_hsm_error instanceof EnrollmentError, "NoHSMError should extend EnrollmentError");
    assert.ok(no_hsm_error instanceof OneIDError, "NoHSMError should extend OneIDError");

    const network_error = new NetworkError("test");
    assert.ok(network_error instanceof OneIDError, "NetworkError should extend OneIDError");
    assert.ok(!(network_error instanceof EnrollmentError), "NetworkError should NOT extend EnrollmentError");
  });

  it("should preserve error codes", () => {
    const error = new NoHSMError("no tpm found");
    assert.equal(error.error_code, "NO_HSM_FOUND");
    assert.equal(error.message, "no tpm found");
    assert.equal(error.name, "NoHSMError");
  });
});

describe("SDK version and types (offline)", () => {
  it("should report correct SDK version", () => {
    assert.equal(VERSION, "0.1.0");
  });

  it("should have all trust tiers", () => {
    assert.equal(TrustTier.SOVEREIGN, "sovereign");
    assert.equal(TrustTier.SOVEREIGN_PORTABLE, "sovereign-portable");
    assert.equal(TrustTier.LEGACY, "legacy");
    assert.equal(TrustTier.VIRTUAL, "virtual");
    assert.equal(TrustTier.ENCLAVE, "enclave");
    assert.equal(TrustTier.DECLARED, "declared");
  });

  it("should have all key algorithms", () => {
    assert.equal(KeyAlgorithm.ED25519, "ed25519");
    assert.equal(KeyAlgorithm.ECDSA_P256, "ecdsa-p256");
    assert.equal(KeyAlgorithm.ECDSA_P384, "ecdsa-p384");
    assert.equal(KeyAlgorithm.RSA_2048, "rsa-2048");
    assert.equal(KeyAlgorithm.RSA_4096, "rsa-4096");
  });
});

describe("Input validation (offline)", () => {
  it("should reject invalid trust tier", async () => {
    await assert.rejects(
      () => enroll({ request_tier: "nonexistent-tier" }),
      (error: Error) => {
        assert.ok(error.message.includes("Invalid trust tier"));
        return true;
      },
    );
  });

  it("should reject invalid key algorithm", async () => {
    await assert.rejects(
      () => enroll({ request_tier: "declared", key_algorithm: "bogus-algo" }),
      (error: Error) => {
        assert.ok(error.message.includes("Invalid key algorithm"));
        return true;
      },
    );
  });
});

// =====================================================================
// LIVE ENROLLMENT TEST (requires network + working server)
// =====================================================================

describe("Live declared-tier enrollment (requires server)", () => {
  let backed_up_credentials_exist = false;
  const credentials_file_path = get_credentials_file_path();
  const backup_path = credentials_file_path + BACKUP_SUFFIX;

  before(() => {
    if (fs.existsSync(credentials_file_path)) {
      fs.copyFileSync(credentials_file_path, backup_path);
      backed_up_credentials_exist = true;
      fs.unlinkSync(credentials_file_path);
    }
  });

  after(() => {
    if (backed_up_credentials_exist && fs.existsSync(backup_path)) {
      if (fs.existsSync(credentials_file_path)) {
        fs.unlinkSync(credentials_file_path);
      }
      fs.renameSync(backup_path, credentials_file_path);
    }
  });

  it("should enroll at declared tier with ed25519 key", async () => {
    if (credentials_exist()) {
      delete_credentials();
    }

    let identity;
    try {
      identity = await enroll({
        request_tier: "declared",
        key_algorithm: "ed25519",
      });
    } catch (error) {
      if (error instanceof NetworkError || (error instanceof Error && error.message.includes("500"))) {
        console.log("  SKIPPED: Server unavailable or returned 500. This is a server issue, not an SDK issue.");
        return; // Skip test gracefully
      }
      throw error;
    }

    // Verify the identity object
    assert.ok(identity.internal_id, "internal_id should be non-empty");
    assert.ok(identity.internal_id.startsWith("1id_"), `internal_id should start with '1id_', got: ${identity.internal_id}`);
    assert.ok(identity.handle, "handle should be non-empty");
    assert.ok(identity.handle.startsWith("@"), `handle should start with '@', got: ${identity.handle}`);
    assert.equal(identity.trust_tier, TrustTier.DECLARED);
    assert.equal(identity.hsm_type, HSMType.SOFTWARE);
    assert.equal(identity.key_algorithm, KeyAlgorithm.ED25519);
    assert.ok(identity.enrolled_at instanceof Date, "enrolled_at should be a Date");
    assert.equal(identity.device_count, 0, "declared tier should have device_count 0");

    console.log(`  Enrolled: ${identity.handle} (${identity.internal_id})`);
    console.log(`  Trust tier: ${identity.trust_tier}`);
    console.log(`  Key algorithm: ${identity.key_algorithm}`);

    // Verify whoami works with the live enrollment
    const me = whoami();
    assert.ok(me.internal_id.startsWith("1id_"));
    assert.equal(me.trust_tier, TrustTier.DECLARED);
    console.log(`  whoami(): ${me.handle}`);
  });
});
