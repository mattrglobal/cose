/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { ByteArray } from "./common";
import { NormalizedCoseHeaders } from "./NormalizedCoseHeaders";

/**
 * @ignore
 */
export const enum CoseSignStructure {
  COSESign,
  COSESign1,
}

/**
 * @ignore
 */
export interface DecodedSingleSignResult {
  /**
   * Indicates whether the decoded COSE_Sign structure included a COSE tag
   */
  readonly tagged: boolean;
  /**
   * The array of protected headers that were signed in the COSE_Sign1 structure
   */
  readonly protectedHeaders: NormalizedCoseHeaders;
  /**
   * The encoded version of the protected headers that were signed in the COSE_Sign1 structure
   */
  readonly encodedProtectedHeaders: Uint8Array;
  /**
   * The array of un-protected headers that were included in the COSE_Sign1 structure
   */
  readonly unProtectedHeaders: NormalizedCoseHeaders;
  /**
   * The encoded version of the un-protected headers that were included in the COSE_Sign1 structure
   */
  readonly encodedUnProtectedHeaders: Uint8Array;
  /**
   * The payload decoded that was signed
   */
  readonly payload: unknown;
  /**
   * The payload as it was signed in the COSE_Sign1 structure
   */
  readonly encodedPayload: Uint8Array;
  /**
   * The raw signature value in the COSE_Sign1 structure
   */
  readonly signature: Uint8Array;
  /**
   * The COSE_Sign1 structure type
   */
  readonly structureType: CoseSignStructure.COSESign1;
}

/**
 * @ignore
 */
export interface DecodedSignerResult {
  /**
   * The array of protected headers that were signed in the COSE_Sign1 structure
   */
  readonly protectedHeaders: NormalizedCoseHeaders;
  /**
   * The encoded version of the protected headers that were signed in the COSE_Sign1 structure
   */
  readonly encodedProtectedHeaders: Uint8Array;
  /**
   * The array of un-protected headers that were included in the COSE_Sign1 structure
   */
  readonly unProtectedHeaders: NormalizedCoseHeaders;
  /**
   * The encoded version of the un-protected headers that were included in the COSE_Sign1 structure
   */
  readonly encodedUnProtectedHeaders: Uint8Array;
  /**
   * The raw signature value in the COSE_Sign1 structure
   */
  readonly signature: Uint8Array;
}

/**
 * @ignore
 */
export interface DecodedMultiSignResult {
  /**
   * Indicates whether the decoded COSE_Sign structure included a COSE tag
   */
  readonly tagged: boolean;
  /**
   * The array of protected headers that were signed in the COSE_Sign structure
   */
  readonly protectedHeaders: NormalizedCoseHeaders;
  /**
   * The encoded version of the protected headers that were signed in the COSE_Sign structure
   */
  readonly encodedProtectedHeaders: Uint8Array;
  /**
   * The array of un-protected headers that were included in the COSE_Sign structure
   */
  readonly unProtectedHeaders: NormalizedCoseHeaders;
  /**
   * The encoded version of the un-protected headers that were included in the COSE_Sign structure
   */
  readonly encodedUnProtectedHeaders: Uint8Array;
  /**
   * The payload decoded that was signed
   */
  readonly payload: unknown;
  /**
   * The payload as it was signed in the COSE_Sign1 structure
   */
  readonly encodedPayload: ByteArray;
  /**
   * The signers included in the COSE_Sign structure
   */
  readonly signers: DecodedSignerResult[];
  /**
   * The raw signature value in the COSE_Sign1 structure
   */
  readonly structureType: CoseSignStructure.COSESign;
}

/**
 * @ignore
 */
export type DecodedPayloadResult = DecodedSingleSignResult | DecodedMultiSignResult;
