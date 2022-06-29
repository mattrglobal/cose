/**
 * @ignore
 */
export enum CoseErrorTypes {
  CryptoError = "CryptoError",
  DecodeError = "DecodeError",
  ExternalSignerFunctionError = "ExternalSignerFunctionError",
  ExternalVerifierFunctionError = "ExternalVerifierFunctionError",
  NotImplementedError = "NotImplementedError",
  SignError = "SignError",
  ValidationError = "ValidationError",
  VerifyError = "VerifyError",
}

type CoseErrorOptions = {
  message: string;
  type: CoseErrorTypes;
  details?: unknown;
};

export class CoseError extends Error {
  public type: CoseErrorTypes;
  public details: unknown;
  constructor(options: CoseErrorOptions) {
    const { message, type, details } = options;
    super(message);
    Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
    this.type = type;
    this.details = details;
    Error.captureStackTrace(this);
  }
}

export function isCoseError(error: unknown, type?: string): error is CoseError {
  return !!(error && error instanceof CoseError && (!type || type === error.type));
}
