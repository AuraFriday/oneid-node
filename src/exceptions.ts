/**
 * Exception hierarchy for the 1id.com Node.js SDK.
 *
 * All exceptions inherit from OneIDError. Enrollment-specific exceptions
 * inherit from EnrollmentError. The hierarchy is designed so callers can
 * catch at any level of specificity:
 *
 *     try {
 *       await oneid.enroll({ requestTier: "sovereign" });
 *     } catch (e) {
 *       if (e instanceof NoHSMError) { ... }
 *       else if (e instanceof EnrollmentError) { ... }
 *       else if (e instanceof OneIDError) { ... }
 *     }
 *
 * CRITICAL DESIGN RULE: requestTier is a REQUIREMENT, not a preference.
 * These exceptions are raised when the requested tier CANNOT be satisfied.
 * The SDK NEVER silently falls back to a lower tier.
 */

/**
 * Base error for all 1id.com SDK errors.
 */
export class OneIDError extends Error {
  public readonly error_code: string | null;

  constructor(message: string = "An error occurred in the 1id SDK", error_code: string | null = null) {
    super(message);
    this.name = "OneIDError";
    this.error_code = error_code;
    // Restore prototype chain (needed for instanceof to work with TS class extends Error)
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Base error for all enrollment failures.
 */
export class EnrollmentError extends OneIDError {
  constructor(message: string = "Enrollment failed", error_code: string | null = null) {
    super(message, error_code);
    this.name = "EnrollmentError";
  }
}

/**
 * Requested trust tier requires an HSM but none was found.
 */
export class NoHSMError extends EnrollmentError {
  constructor(message: string = "No hardware security module found") {
    super(message, "NO_HSM_FOUND");
    this.name = "NoHSMError";
  }
}

/**
 * User denied the elevation prompt (clicked No on UAC/sudo/pkexec).
 */
export class UACDeniedError extends EnrollmentError {
  constructor(message: string = "User denied elevation prompt") {
    super(message, "UAC_DENIED");
    this.name = "UACDeniedError";
  }
}

/**
 * HSM was found but could not be accessed.
 */
export class HSMAccessError extends EnrollmentError {
  constructor(message: string = "HSM found but access failed") {
    super(message, "HSM_ACCESS_ERROR");
    this.name = "HSMAccessError";
  }
}

/**
 * This HSM is already enrolled with a different identity.
 */
export class AlreadyEnrolledError extends EnrollmentError {
  constructor(message: string = "This HSM is already enrolled with a different identity") {
    super(message, "EK_ALREADY_REGISTERED");
    this.name = "AlreadyEnrolledError";
  }
}

/**
 * Requested vanity handle is already in use by another identity.
 */
export class HandleTakenError extends EnrollmentError {
  constructor(message: string = "Requested handle is already in use") {
    super(message, "HANDLE_TAKEN");
    this.name = "HandleTakenError";
  }
}

/**
 * Requested handle violates naming rules.
 */
export class HandleInvalidError extends EnrollmentError {
  constructor(message: string = "Requested handle violates naming rules") {
    super(message, "HANDLE_INVALID");
    this.name = "HandleInvalidError";
  }
}

/**
 * Requested handle was previously used and is permanently retired.
 */
export class HandleRetiredError extends EnrollmentError {
  constructor(message: string = "Handle was previously used and is permanently retired") {
    super(message, "HANDLE_RETIRED");
    this.name = "HandleRetiredError";
  }
}

/**
 * Token acquisition or refresh failed.
 */
export class AuthenticationError extends OneIDError {
  constructor(message: string = "Authentication failed") {
    super(message, "AUTH_FAILED");
    this.name = "AuthenticationError";
  }
}

/**
 * Could not reach the 1id.com API server.
 */
export class NetworkError extends OneIDError {
  constructor(message: string = "Could not reach 1id.com") {
    super(message, "NETWORK_ERROR");
    this.name = "NetworkError";
  }
}

/**
 * No enrollment credentials found on this machine.
 */
export class NotEnrolledError extends OneIDError {
  constructor(message: string = "Not enrolled -- call oneid.enroll() first") {
    super(message, "NOT_ENROLLED");
    this.name = "NotEnrolledError";
  }
}

/**
 * The oneid-enroll Go binary could not be found or downloaded.
 */
export class BinaryNotFoundError extends OneIDError {
  constructor(message: string = "oneid-enroll binary not found and could not be downloaded") {
    super(message, "BINARY_NOT_FOUND");
    this.name = "BinaryNotFoundError";
  }
}

/**
 * Too many enrollment attempts from this IP address.
 */
export class RateLimitExceededError extends EnrollmentError {
  constructor(message: string = "Rate limit exceeded -- too many enrollment attempts") {
    super(message, "RATE_LIMIT_EXCEEDED");
    this.name = "RateLimitExceededError";
  }
}

// -- Mapping from server API error codes to exception classes --
const SERVER_ERROR_CODE_TO_EXCEPTION_CLASS: Record<string, new (message: string) => OneIDError> = {
  "EK_ALREADY_REGISTERED": AlreadyEnrolledError,
  "EK_CERT_INVALID": EnrollmentError,
  "EK_CERT_CHAIN_UNTRUSTED": EnrollmentError,
  "HANDLE_TAKEN": HandleTakenError,
  "HANDLE_INVALID": HandleInvalidError,
  "HANDLE_RETIRED": HandleRetiredError,
  "RATE_LIMIT_EXCEEDED": RateLimitExceededError,
  "RATE_LIMITED": RateLimitExceededError,
};

/**
 * Raise the appropriate exception for a server error response.
 */
export function raise_from_server_error_response(error_code: string, error_message: string): never {
  const ExceptionClass = SERVER_ERROR_CODE_TO_EXCEPTION_CLASS[error_code] ?? EnrollmentError;
  throw new ExceptionClass(error_message);
}
