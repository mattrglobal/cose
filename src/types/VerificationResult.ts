/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

export interface VerificationResult {
  /**
   * Indicates whether the signature verification was successful
   */
  readonly verified: boolean;
  /**
   * The payload decoded that was signed
   */
  readonly payload: unknown;
}
