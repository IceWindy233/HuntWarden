export type SecurityErrorCode =
  | "TARGET_UNAVAILABLE"
  | "PERMISSION_DENIED"
  | "TOOL_TIMEOUT"
  | "UNSUPPORTED_ENVIRONMENT"
  | "INVALID_TARGET"
  | "INVALID_ARGUMENT"
  | "EVIDENCE_COLLECTION"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_MISMATCH"
  | "BUDGET_EXCEEDED"
  | "RECOVERY_UNCERTAIN";

export class SecurityError extends Error {
  constructor(
    public readonly code: SecurityErrorCode,
    message: string,
    public readonly details?: Record<string, unknown>,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "SecurityError";
  }
}

export class TargetUnavailableError extends SecurityError {
  constructor(message: string, options?: ErrorOptions) {
    super("TARGET_UNAVAILABLE", message, undefined, options);
  }
}

export class PermissionDeniedError extends SecurityError {
  constructor(message: string, options?: ErrorOptions) {
    super("PERMISSION_DENIED", message, undefined, options);
  }
}

export class ToolTimeoutError extends SecurityError {
  constructor(message: string) {
    super("TOOL_TIMEOUT", message);
  }
}

export class InvalidArgumentError extends SecurityError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("INVALID_ARGUMENT", message, details);
  }
}
