/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import {
  COSE_SIGN,
  COSE_SIGN_1,
  CoseHeaderParameterEnum,
  isMultiSignOptions,
  MultiSignOptions,
  Sign1Tag,
  SignOptions,
  SignTag,
  SingleSignOptions,
  SingleSignDecodedResult,
  MultiSignDecodedResult,
  MultiSignSignature,
} from "./types";
import { EMPTY_BUFFER, encodeCoseHeaders, getHeader, normalizeCoseHeaderParameters, signPayload } from "./utilities";

import { Buffer } from "buffer";
import cbor, { Tagged } from "./cbor";
import { signData } from "./crypto";
import { assertSignOptions } from "./types/SignOptions";
import { isByteArray } from "./types/common";
import { CoseError, CoseErrorTypes } from "./common/error";
import { SignResult } from "./types/SignResult";

/* eslint-disable @typescript-eslint/no-explicit-any */

const singleSign = async (options: SingleSignOptions): Promise<Uint8Array | SingleSignDecodedResult> => {
  let { unprotectedHeaders, protectedHeaders } = options;
  const { payload, additionalAuthenticatedData } = options;

  const { algorithm, privateKey } = options;
  let { externalSigner } = options;

  protectedHeaders = protectedHeaders ?? {};
  unprotectedHeaders = unprotectedHeaders ?? {};

  const convertedUnprotectedHeaders = unprotectedHeaders
    ? normalizeCoseHeaderParameters(unprotectedHeaders)
    : undefined;
  const convertedProtectedHeaders = protectedHeaders
    ? normalizeCoseHeaderParameters(protectedHeaders)
    : new Map<string | number, any>();

  const existingAlgorithm = getHeader(
    {
      protectedHeaders: convertedProtectedHeaders ?? new Map<string | number, any>(),
      unProtectedHeaders: convertedUnprotectedHeaders ?? new Map<string | number, any>(),
    },
    CoseHeaderParameterEnum.alg
  );

  if (!existingAlgorithm) {
    convertedProtectedHeaders.set(CoseHeaderParameterEnum.alg, existingAlgorithm ?? algorithm);
  }

  const encodedProtectedHeaders = encodeCoseHeaders(convertedProtectedHeaders);

  let usingExternalSigner = true;
  if (!externalSigner) {
    if (!privateKey) {
      throw new CoseError({
        type: CoseErrorTypes.SignError,
        message: "Either signer or key argument must be supplied",
        details: {},
      });
    }
    externalSigner = (payload: Uint8Array): Promise<Uint8Array> => signData(algorithm, payload, privateKey);
    usingExternalSigner = false;
  }

  const signaturePayload = [COSE_SIGN_1, encodedProtectedHeaders, additionalAuthenticatedData ?? EMPTY_BUFFER, payload];

  const signature = await signPayload(externalSigner, cbor.encodeCanonical(signaturePayload), usingExternalSigner);

  const result: SingleSignDecodedResult = [
    encodedProtectedHeaders,
    convertedUnprotectedHeaders,
    payload,
    Buffer.from(signature),
  ];

  if (options.skipEncodingResult) {
    return result;
  }

  return new Uint8Array(cbor.encodeCanonical(options.skipTag ? result : new Tagged(Sign1Tag, result)));
};

const multiSign = async (options: MultiSignOptions): Promise<Uint8Array | MultiSignDecodedResult> => {
  const { unprotectedHeaders, protectedHeaders } = options;
  const { payload, additionalAuthenticatedData } = options;

  const convertedUnprotectedHeaders = unprotectedHeaders
    ? normalizeCoseHeaderParameters(unprotectedHeaders)
    : undefined;
  const convertedProtectedHeaders = protectedHeaders
    ? normalizeCoseHeaderParameters(protectedHeaders)
    : new Map<string | number, any>();

  const encodedProtectedHeaders = encodeCoseHeaders(convertedProtectedHeaders);

  const signatures: MultiSignSignature[] = await Promise.all(
    options.signers.map(async (signer) => {
      let { externalSigner } = signer;
      const { privateKey, algorithm, protectedHeaders } = signer;

      if (!externalSigner && !privateKey) {
        throw new CoseError({
          type: CoseErrorTypes.SignError,
          message: "Either signer or key argument must be supplied",
          details: {},
        });
      }

      let convertedSignerProtectedHeaders;
      if (protectedHeaders) {
        convertedSignerProtectedHeaders = normalizeCoseHeaderParameters(protectedHeaders);
      }
      const encodedSignerProtectedHeaders = encodeCoseHeaders(convertedSignerProtectedHeaders);

      let usingExternalSigner = true;
      if (!externalSigner) {
        externalSigner = (payload: Uint8Array): Promise<Uint8Array> => signData(algorithm, payload, privateKey);
        usingExternalSigner = false;
      }

      const signaturePayload = [
        COSE_SIGN,
        encodedProtectedHeaders,
        encodedSignerProtectedHeaders,
        additionalAuthenticatedData ?? EMPTY_BUFFER,
        payload,
      ];

      const signature = await signPayload(externalSigner, cbor.encodeCanonical(signaturePayload), usingExternalSigner);

      return [encodedProtectedHeaders, convertedUnprotectedHeaders, Buffer.from(signature)];
    })
  );

  const result: MultiSignDecodedResult = [
    encodedProtectedHeaders,
    convertedUnprotectedHeaders,
    payload,
    [...signatures],
  ];

  if (options.skipEncodingResult) {
    return result;
  }

  return new Uint8Array(cbor.encodeCanonical(options.skipTag ? result : new Tagged(SignTag, result)));
};

export const sign = async <T extends SignOptions>(options: T): Promise<SignResult<T>> => {
  assertSignOptions(options);

  // TEMPORARY
  if (options.payload === undefined) {
    throw new Error("Expected SignOptions");
  }

  if (!options.skipEncodingPayload) {
    options = { ...options, payload: cbor.encode(options.payload) };
  } else if (!isByteArray(options.payload)) {
    throw new CoseError({
      type: CoseErrorTypes.SignError,
      message: "Expected options.payload type to be binary if skipEncodingPayload = true",
      details: {},
    });
  }

  if (isMultiSignOptions(options)) {
    return multiSign(options) as Promise<SignResult<T>>;
  }

  return singleSign(options) as Promise<SignResult<T>>;
};
