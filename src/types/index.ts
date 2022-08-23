/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

export { CoseHeaders } from "./CoseHeaders";
export { SignerFunction } from "./SignerFunction";
export { assertSingleSignOptions, SingleSignOptions, isSingleSignOptions } from "./SingleSignOptions";
export { assertMultiSignOptions, MultiSignOptions, isMultiSignOptions } from "./MultiSignOptions";
export { assertSignOptions, SignOptions } from "./SignOptions";
export { assertVerifyOptions, VerifyOptions, VerifierFunction } from "./VerifyOptions";
export { VerificationResult } from "./VerificationResult";
export { ConverterMap } from "./ConverterMap";
export { NormalizedCoseHeaders } from "./NormalizedCoseHeaders";
export { CoseKey, assertCoseKey } from "./CoseKey";
export * from "./iana";
export * from "./JsonWebKey";
export * from "./MultiSignDecodedResult";
export * from "./SingleSignDecodedResult";
export { DecodedPayloadResult } from "./DecodedPayloadResult";

/**
 * String constant acting as a domain separator for COSE structure Sign1
 */
export const COSE_SIGN_1 = "Signature1";

/**
 * String constant acting as a domain separator for COSE structure Sign
 */
export const COSE_SIGN = "Signature";

/**
 * CBOR tag for denoting a COSE Sign structure
 */
export const SignTag = 98;

/**
 * CBOR tag for denoting a COSE Sign1 structure
 */
export const Sign1Tag = 18;
