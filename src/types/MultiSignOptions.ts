/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Buffer } from "buffer";
import { CoseSignatureAlgorithmEnum } from "./iana";
import { CoseHeaders } from "./CoseHeaders";
import { SignerFunction } from "./SignerFunction";
import { z } from "zod";
import { assertType, isType } from "./common";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * @ignore
 */
export interface Signer {
  /**
   * Algorithm
   */
  readonly algorithm: number;
  /**
   * An array of protected headers to include in the signed structure
   * when structure is COSE_Sign
   */
  readonly protectedHeaders?: CoseHeaders;
  /**
   * An array of unprotected headers to include in the signed structure
   * when structure is COSE_Sign
   */
  readonly unprotectedHeaders?: CoseHeaders;
  /**
   * Function for handling the cryptographic signing operation
   *
   * Note - either this parameter or the *key* parameter MUST be present
   */
  readonly externalSigner?: SignerFunction;
  /**
   * Private key used to perform cryptographic signing operation
   *
   * Note - either this parameter or the *signer* parameter MUST be present
   */
  readonly privateKey?: any;
}

/**
 * @ignore
 */
export interface MultiSignOptions {
  /**
   * An array of protected headers to include in the signed structure
   */
  readonly protectedHeaders?: CoseHeaders;
  /**
   * An array of unprotected headers to include in the signed structure
   */
  readonly unprotectedHeaders?: CoseHeaders;
  /**
   * Additional authenticated data
   */
  readonly additionalAuthenticatedData?: any;
  /**
   * Payload to be signed
   */
  readonly payload: any;
  /**
   * Indicates whether to skip CBOR encoding the payload (only allowed in the type of the supplied payload
   * is binary)
   */
  readonly skipEncodingPayload?: boolean;
  /**
   * Indicates whether to tag the resulting output with a CBOR tag structure.
   *
   * Note - The tag will always be skipped when encoding of the result is skipped.
   */
  readonly skipTag?: boolean;
  /**
   * Signer or Array of Signers
   */
  readonly signers: readonly Signer[];
  /**
   * Indicates whether to skip CBOR encoding of the signing result.
   *
   * Note - When true, the tag will always be skipped.
   */
  readonly skipEncodingResult?: boolean;
}

/**
 * @ignore
 */
const signerValidator = z.object({
  algorithm: z.nativeEnum(CoseSignatureAlgorithmEnum),
  protectedHeaders: z.object({}).optional(),
  unprotectedHeaders: z.object({}).optional(),
  externalSigner: z.function().optional(),
  privateKey: z.union([z.object({}), z.string(), z.number(), z.any().array(), z.boolean(), z.number()]).optional(),
});

/**
 * @ignore
 */
export const isSigner = isType<Signer>(signerValidator);

/**
 * @ignore
 */
export const MultiSignOptionsValidator = z.object({
  protectedHeaders: z.object({}).optional(),
  unprotectedHeaders: z.object({}).optional(),
  additionalAuthenticatedData: z.object({}).optional(),
  payload: z.union([
    z.instanceof(Uint8Array),
    z.instanceof(Buffer),
    z.object({}),
    z.string(),
    z.number(),
    z.any().array(),
    z.boolean(),
    z.number(),
    z.map(z.any(), z.any()),
  ]),
  skipEncodingPayload: z.boolean().optional(),
  skipTag: z.boolean().optional(),
  signers: signerValidator.array(),
});

/**
 * @ignore
 */
export const isMultiSignOptions = isType<MultiSignOptions>(MultiSignOptionsValidator);

/**
 * @ignore
 */
export const assertMultiSignOptions = assertType<MultiSignOptions>(
  MultiSignOptionsValidator,
  "Expected MultiSignOptions"
);
