#!/usr/bin/env node
/**
 * Command-line interface for the 1id.com SDK (Node.js).
 *
 * Usage:
 *     oneid whoami          -- Show enrolled identity info
 *     oneid token           -- Print a fresh bearer token (for scripting)
 *     oneid enroll          -- Enroll this machine
 *     oneid status          -- Check if enrolled
 *
 * Examples:
 *     oneid enroll --tier declared --email owner@example.com
 *     TOKEN=$(oneid token)
 *     curl -H "Authorization: Bearer $TOKEN" https://api.example.com/
 */

import { credentials_exist, load_credentials, get_credentials_file_path, delete_credentials } from "./credentials.js";
import { enroll } from "./enroll.js";
import { get_token } from "./auth.js";
import { TrustTier, format_identity_as_display_string } from "./identity.js";

const VERSION = "0.1.0";

function print_help(): void {
  console.log(`oneid ${VERSION} -- 1id.com identity for AI agents

Usage: oneid <command> [options]

Commands:
  whoami              Show enrolled identity info
  token               Print a fresh bearer token
  enroll              Enroll this machine with 1id.com
  status              Check enrollment status

Enroll options:
  --tier <tier>       Trust tier: sovereign, declared, etc. (default: declared)
  --email <email>     Operator email for handle purchases
  --handle <name>     Requested vanity handle
  --force             Re-enroll even if already enrolled

Token options:
  --json              Output as JSON (includes expiry)
  --refresh           Force token refresh

Whoami options:
  --json              Output as JSON

Global:
  --version           Show version
  --help              Show this help`);
}

function parse_named_argument(args: string[], flag_name: string): string | undefined {
  const flag_index = args.indexOf(flag_name);
  if (flag_index !== -1 && flag_index + 1 < args.length) {
    return args[flag_index + 1];
  }
  return undefined;
}

function has_flag(args: string[], flag_name: string): boolean {
  return args.includes(flag_name);
}

async function command_whoami(args: string[]): Promise<number> {
  const output_as_json = has_flag(args, "--json");

  if (!credentials_exist()) {
    console.error("Not enrolled. Run: oneid enroll");
    return 1;
  }

  try {
    const credentials = load_credentials();
    const info = {
      internal_id: credentials.client_id,
      trust_tier: credentials.trust_tier,
      key_algorithm: credentials.key_algorithm,
      enrolled_at: credentials.enrolled_at || null,
    };

    if (output_as_json) {
      console.log(JSON.stringify(info, null, 2));
    } else {
      console.log(`Identity:   ${info.internal_id}`);
      console.log(`Trust tier: ${info.trust_tier}`);
      console.log(`Algorithm:  ${info.key_algorithm}`);
      if (info.enrolled_at) {
        console.log(`Enrolled:   ${info.enrolled_at}`);
      }
    }
    return 0;
  } catch (error: any) {
    console.error(`Error: ${error.message}`);
    return 1;
  }
}

async function command_token(args: string[]): Promise<number> {
  const output_as_json = has_flag(args, "--json");
  const force_refresh = has_flag(args, "--refresh");

  if (!credentials_exist()) {
    console.error("Not enrolled. Run: oneid enroll");
    return 1;
  }

  try {
    const token = await get_token(force_refresh);

    if (output_as_json) {
      console.log(JSON.stringify({
        access_token: token.access_token,
        token_type: token.token_type,
        expires_in: token.expires_in,
      }, null, 2));
    } else {
      // Raw token for scripting: $(oneid token)
      console.log(token.access_token);
    }
    return 0;
  } catch (error: any) {
    console.error(`Authentication failed: ${error.message}`);
    return 1;
  }
}

async function command_enroll(args: string[]): Promise<number> {
  const request_tier = parse_named_argument(args, "--tier") || "declared";
  const operator_email = parse_named_argument(args, "--email");
  const requested_handle = parse_named_argument(args, "--handle");
  const force_reenroll = has_flag(args, "--force");

  if (credentials_exist() && !force_reenroll) {
    console.error("Already enrolled. Use --force to re-enroll (replaces current identity).");
    return 1;
  }

  if (force_reenroll && credentials_exist()) {
    delete_credentials();
  }

  try {
    const identity = await enroll({
      request_tier: request_tier as TrustTier,
      operator_email: operator_email,
      requested_handle: requested_handle,
    });

    console.log("Enrolled successfully!");
    console.log(`Identity:   ${identity.internal_id}`);
    console.log(`Handle:     ${identity.handle}`);
    console.log(`Trust tier: ${identity.trust_tier}`);
    return 0;
  } catch (error: any) {
    console.error(`Enrollment failed: ${error.message}`);
    return 1;
  }
}

async function command_status(_args: string[]): Promise<number> {
  const credentials_file_path = get_credentials_file_path();

  if (credentials_exist()) {
    console.log("Enrolled: yes");
    console.log(`Credentials: ${credentials_file_path}`);
    try {
      const credentials = load_credentials();
      console.log(`Identity: ${credentials.client_id}`);
      console.log(`Tier: ${credentials.trust_tier}`);
    } catch {
      console.log("Identity: (unable to read)");
    }
    return 0;
  } else {
    console.log("Enrolled: no");
    console.log(`Expected credentials at: ${credentials_file_path}`);
    return 1;
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || has_flag(args, "--help") || has_flag(args, "-h")) {
    print_help();
    process.exit(0);
  }

  if (has_flag(args, "--version") || has_flag(args, "-v")) {
    console.log(`oneid ${VERSION}`);
    process.exit(0);
  }

  const command = args[0];
  const command_args = args.slice(1);

  let exit_code: number;
  switch (command) {
    case "whoami":
      exit_code = await command_whoami(command_args);
      break;
    case "token":
      exit_code = await command_token(command_args);
      break;
    case "enroll":
      exit_code = await command_enroll(command_args);
      break;
    case "status":
      exit_code = await command_status(command_args);
      break;
    default:
      console.error(`Unknown command: ${command}`);
      print_help();
      exit_code = 1;
  }

  process.exit(exit_code);
}

main();
