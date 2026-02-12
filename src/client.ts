/**
 * HTTP client for the 1id.com Enrollment API.
 *
 * Uses Node.js built-in `https`/`http` modules -- zero external dependencies.
 *
 * Handles all HTTP communication with the 1id.com server, including:
 * - Enrollment requests (declared and sovereign tiers)
 * - Identity lookups
 * - Handle management
 * - Error response mapping to SDK exceptions
 *
 * All responses follow the 1id.com API envelope:
 *   {"ok": true, "data": {...}, "error": null}
 *   {"ok": false, "data": null, "error": {"code": "...", "message": "..."}}
 */

import * as https from "node:https";
import * as http from "node:http";
import { DEFAULT_API_BASE_URL } from "./credentials.js";
import {
  EnrollmentError,
  NetworkError,
  raise_from_server_error_response,
} from "./exceptions.js";

// -- HTTP client configuration --
const DEFAULT_HTTP_TIMEOUT_MILLISECONDS = 30_000;
const USER_AGENT = "oneid-sdk-node/0.1.0";

interface RequestOptions {
  method: string;
  path: string;
  json_body?: Record<string, unknown> | null;
  headers?: Record<string, string>;
}

/**
 * Make a raw HTTP(S) request and return the parsed JSON body.
 * Uses only Node.js built-in modules.
 */
function make_http_request(
  base_url: string,
  options: RequestOptions,
  timeout_milliseconds: number,
): Promise<{ status_code: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const url = new URL(options.path, base_url);
    const is_https = url.protocol === "https:";
    const transport = is_https ? https : http;

    const request_headers: Record<string, string> = {
      "User-Agent": USER_AGENT,
      "Accept": "application/json",
      ...options.headers,
    };

    let request_body_string: string | undefined;
    if (options.json_body != null) {
      request_body_string = JSON.stringify(options.json_body);
      request_headers["Content-Type"] = "application/json";
      request_headers["Content-Length"] = Buffer.byteLength(request_body_string).toString();
    }

    const req = transport.request(
      {
        hostname: url.hostname,
        port: url.port || (is_https ? 443 : 80),
        path: url.pathname + url.search,
        method: options.method,
        headers: request_headers,
        timeout: timeout_milliseconds,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => { chunks.push(chunk); });
        res.on("end", () => {
          const raw_body = Buffer.concat(chunks).toString("utf-8");
          try {
            const parsed_body = JSON.parse(raw_body);
            resolve({ status_code: res.statusCode ?? 0, body: parsed_body });
          } catch {
            reject(new NetworkError(
              `Invalid JSON response from ${url.href} (HTTP ${res.statusCode}): ${raw_body.slice(0, 200)}`
            ));
          }
        });
      },
    );

    req.on("error", (error: Error) => {
      reject(new NetworkError(`Could not connect to ${base_url}: ${error.message}`));
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new NetworkError(
        `Request to ${url.href} timed out after ${timeout_milliseconds}ms`
      ));
    });

    if (request_body_string != null) {
      req.write(request_body_string);
    }
    req.end();
  });
}

/**
 * HTTP client for the 1id.com enrollment and identity API.
 *
 * Wraps Node.js http/https with 1id-specific error handling. All methods
 * throw SDK exceptions on failure, never raw HTTP errors.
 */
export class OneIDAPIClient {
  public readonly api_base_url: string;
  public readonly timeout_milliseconds: number;

  constructor(
    api_base_url: string = DEFAULT_API_BASE_URL,
    timeout_milliseconds: number = DEFAULT_HTTP_TIMEOUT_MILLISECONDS,
  ) {
    this.api_base_url = api_base_url.replace(/\/+$/, "");
    this.timeout_milliseconds = timeout_milliseconds;
  }

  /**
   * Make an HTTP request to the 1id.com API and parse the envelope response.
   */
  private async _make_request(
    method: string,
    api_path: string,
    json_body?: Record<string, unknown> | null,
    headers?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    const response = await make_http_request(
      this.api_base_url,
      { method, path: api_path, json_body, headers },
      this.timeout_milliseconds,
    );

    const response_body = response.body as Record<string, unknown>;

    // Check for the standard 1id error envelope
    if (!response_body?.ok) {
      const error_info = (response_body?.error ?? {}) as Record<string, string>;
      const error_code = error_info.code ?? "UNKNOWN_ERROR";
      const error_message = error_info.message ?? `Server returned HTTP ${response.status_code}`;
      raise_from_server_error_response(error_code, error_message);
    }

    return (response_body.data ?? {}) as Record<string, unknown>;
  }

  /**
   * Enroll a new identity at the declared trust tier (no HSM required).
   */
  async enroll_declared(
    software_key_pem: string,
    key_algorithm: string,
    operator_email?: string | null,
    requested_handle?: string | null,
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      software_key_pem,
      key_algorithm,
    };
    if (operator_email != null) { request_body["operator_email"] = operator_email; }
    if (requested_handle != null) { request_body["requested_handle"] = requested_handle; }

    return this._make_request("POST", "/api/v1/enroll/declared", request_body);
  }

  /**
   * Begin TPM/HSM-based enrollment (sovereign/sovereign-portable tiers).
   */
  async enroll_begin(
    ek_certificate_pem: string,
    ak_public_key_pem: string,
    ak_tpmt_public_b64: string = "",
    ek_public_key_pem: string = "",
    ek_certificate_chain_pem?: string[],
    hsm_type: string = "tpm",
    operator_email?: string | null,
    requested_handle?: string | null,
  ): Promise<Record<string, unknown>> {
    const request_body: Record<string, unknown> = {
      ek_certificate_pem,
      ek_public_key_pem,
      ak_public_key_pem,
      ak_tpmt_public_b64,
      hsm_type,
    };
    if (ek_certificate_chain_pem) { request_body["ek_certificate_chain_pem"] = ek_certificate_chain_pem; }
    if (operator_email != null) { request_body["operator_email"] = operator_email; }
    if (requested_handle != null) { request_body["requested_handle"] = requested_handle; }

    return this._make_request("POST", "/api/v1/enroll/begin", request_body);
  }

  /**
   * Complete TPM/HSM-based enrollment by proving HSM possession.
   */
  async enroll_activate(
    enrollment_session_id: string,
    decrypted_credential: string,
  ): Promise<Record<string, unknown>> {
    return this._make_request("POST", "/api/v1/enroll/activate", {
      enrollment_session_id,
      decrypted_credential,
    });
  }

  /**
   * Look up public identity information for an agent.
   */
  async get_identity(agent_id: string): Promise<Record<string, unknown>> {
    return this._make_request("GET", `/api/v1/identity/${agent_id}`);
  }

  /**
   * Get an OAuth2 access token using the client_credentials grant.
   *
   * NOTE: Keycloak token endpoint expects form-urlencoded, not JSON.
   */
  async get_token_with_client_credentials(
    client_id: string,
    client_secret: string,
  ): Promise<Record<string, unknown>> {
    const token_path = "/realms/agents/protocol/openid-connect/token";
    const form_body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id,
      client_secret,
    }).toString();

    return new Promise((resolve, reject) => {
      const url = new URL(token_path, this.api_base_url);
      const is_https = url.protocol === "https:";
      const transport = is_https ? https : http;

      const req = transport.request(
        {
          hostname: url.hostname,
          port: url.port || (is_https ? 443 : 80),
          path: url.pathname,
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": Buffer.byteLength(form_body).toString(),
            "User-Agent": USER_AGENT,
          },
          timeout: this.timeout_milliseconds,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => { chunks.push(chunk); });
          res.on("end", () => {
            const raw_body = Buffer.concat(chunks).toString("utf-8");
            try {
              const parsed = JSON.parse(raw_body) as Record<string, unknown>;
              if (res.statusCode !== 200) {
                const error_description =
                  (parsed.error_description as string) ??
                  (parsed.error as string) ??
                  `HTTP ${res.statusCode}`;
                reject(new EnrollmentError(
                  `Token request failed (HTTP ${res.statusCode}): ${error_description}`
                ));
                return;
              }
              resolve(parsed);
            } catch {
              reject(new NetworkError(
                `Invalid JSON from token endpoint (HTTP ${res.statusCode}): ${raw_body.slice(0, 200)}`
              ));
            }
          });
        },
      );

      req.on("error", (error: Error) => {
        reject(new NetworkError(
          `Could not connect to token endpoint ${url.href}: ${error.message}`
        ));
      });

      req.on("timeout", () => {
        req.destroy();
        reject(new NetworkError(
          `Token request to ${url.href} timed out after ${this.timeout_milliseconds}ms`
        ));
      });

      req.write(form_body);
      req.end();
    });
  }

  /**
   * Check whether a vanity handle is available.
   */
  async check_handle_availability(handle_name: string): Promise<Record<string, unknown>> {
    return this._make_request("GET", `/api/v1/handle/${handle_name}`);
  }
}
