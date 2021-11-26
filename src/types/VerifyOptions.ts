/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Buffer } from "buffer";
import { JsonWebKeyPublicValidator, JsonWebKeyPublic } from "./JsonWebKey";
import { z } from "zod";
import { assertType, isType } from "./common";

export type VerifierFunction = (payload: Uint8Array, signature: Uint8Array) => Promise<boolean>;

export interface Verifier {
  /**
   * Function for handling the cryptographic verification operation
   *
   * Note - either this parameter or the *key* parameter MUST be present
   */
  readonly externalVerifier?: VerifierFunction;
  /**
   * Public key used to perform cryptographic verification operation
   *
   * Note - either this parameter or the *verifier* parameter MUST be present
   */
  readonly publicKey?: JsonWebKeyPublic;
}

export interface VerifyOptions {
  /**
   * Payload to be verified, MUST be either a COSE_Sign1 or COSE_Sign structure as a Uint8Array
   */
  readonly payload: Uint8Array;
  /**
   * Verifier for verifying the digital signature
   */
  readonly verifier: Verifier | Verifier[];
  /**
   * Additional authenticated data
   */
  readonly additionalAuthenticatedData?:
    | Uint8Array
    | Buffer
    | Record<string, unknown>
    | string
    | number
    | Array<unknown>
    | boolean;
}

const verifierValidator = z.object({
  externalVerifier: z.function().optional(),
  publicKey: z.optional(JsonWebKeyPublicValidator),
});

export const isVerifier = isType<Verifier>(verifierValidator);

/**
 * @ignore
 */
export const VerifyOptionsValidator = z.object({
  payload: z.instanceof(Uint8Array),
  verifier: z.union([verifierValidator, verifierValidator.array()]),
  additionalAuthenticatedData: z
    .union([
      z.instanceof(Uint8Array),
      z.instanceof(Buffer),
      z.object({}),
      z.string(),
      z.number(),
      z.any().array(),
      z.boolean(),
      z.number(),
    ])
    .optional(),
});

/**
 * @ignore
 */
export const assertVerifyOptions = assertType<VerifyOptions>(VerifyOptionsValidator, "Expected VerifyOptions");
