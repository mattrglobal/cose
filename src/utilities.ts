/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import {
  ConverterMap,
  CoseHeaderParameterEnum,
  CoseHeaderParameters,
  CoseHeaderParametersReverseMap,
  CoseSignatureAlgorithms,
  NormalizedCoseHeaders,
  Sign1Tag,
  SignerFunction,
  SignTag,
  VerifierFunction,
} from "./types";
import { CoseHeaders } from "./types/CoseHeaders";

import { Buffer } from "buffer";
import cbor, { Tagged } from "./cbor";
import { CoseSignStructure, DecodedPayloadResult } from "./types/DecodedPayloadResult";
import { isByteArray } from "./types/common";
import { CoseError, CoseErrorTypes } from "./common/error";
import { z } from "zod";

const CoseHeaderParameterConverterMap: ConverterMap = {
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  kid: (value: any) => {
    return Buffer.from(value, "utf8");
  },
  alg: (value: string | number) => {
    if (z.string().safeParse(value).success && !CoseSignatureAlgorithms[value]) {
      throw new Error("Unknown Algorithm: " + value);
    } else if (z.number().safeParse(value).success) {
      // TODO need to validate the algorithm appropriately
      return value;
    }
    return CoseSignatureAlgorithms[value];
  },
  x5bag: (value: Uint8Array) => {
    // TODO review
    return Buffer.from(value);
  },
};

export const normalizeCoseHeaderParameters = (headers: CoseHeaders): NormalizedCoseHeaders => {
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  const result = new Map<number, any>();
  for (const param in headers) {
    if (!CoseHeaderParameters[param]) {
      //TODO rationalize these errors
      throw new Error("Unknown parameter, '" + param + "'");
    }
    let value = headers[param];
    if (CoseHeaderParameterConverterMap[param]) {
      value = CoseHeaderParameterConverterMap[param](headers[param]);
    }
    if (value !== undefined && value !== null) {
      result.set(CoseHeaderParameters[param], value);
    }
  }
  return result;
};

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
export const getHeaderParameter = (parameter: string | number, decodedPayload: DecodedPayloadResult): any => {
  let result;
  if (decodedPayload.protectedHeaders && decodedPayload.protectedHeaders.get) {
    result = decodedPayload.protectedHeaders.get(parameter);
  }
  if (!result && decodedPayload.unProtectedHeaders && decodedPayload.unProtectedHeaders.get) {
    result = decodedPayload.unProtectedHeaders.get(parameter);
  }
  return result;
};

/**
 * Encodes an empty map in CBOR
 */
export const EMPTY_MAP = cbor.encode({});

/**
 * Represents an empty buffer
 */
export const EMPTY_BUFFER = Buffer.alloc(0);

/**
 * Encode a set of COSE headers
 */
export const encodeCoseHeaders = (headers: NormalizedCoseHeaders | undefined): Buffer => {
  return !headers || headers.size === 0 ? EMPTY_MAP : cbor.encode(headers);
};

/**
 * Signs the payload
 * @param signer signer function to perform the cryptographic sign operation with
 * @param payload payload to sign
 * @param usingExternalSigner indicates whether the sign operation is using an external signer function
 */
export const signPayload = async (
  signer: SignerFunction,
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  payload: any,
  usingExternalSigner: boolean
): Promise<Uint8Array> => {
  try {
    // TODO we should be validating the return type and signature size returned when an external signer function is used?
    return await signer(new Uint8Array(payload));
  } catch (ex) {
    if (usingExternalSigner) {
      throw new CoseError({
        type: CoseErrorTypes.ExternalSignerFunctionError,
        message: "Calling externally supplied signer function failed",
        details: {
          rawError: ex,
        },
      });
    }
    // Otherwise re throw exception from default signer function
    throw ex;
  }
};

export const verifyPayload = async (
  verifier: VerifierFunction,
  payload: Uint8Array,
  signature: Uint8Array,
  usingExternalVerifier: boolean
): Promise<boolean> => {
  try {
    return await verifier(new Uint8Array(payload), new Uint8Array(signature));
  } catch (ex) {
    if (usingExternalVerifier) {
      throw new CoseError({
        type: CoseErrorTypes.ExternalVerifierFunctionError,
        message: "Calling externally supplied verifier function failed",
        details: {
          rawError: ex,
        },
      });
    }
    // Otherwise re throw exception from default signer function
    throw ex;
  }
};

/**
 * As documented in @see https://datatracker.ietf.org/doc/html/rfc8152#section-3
 */
const ZERO_LENGTH_MAP_STRING_ENCODING = "a0";

/**
 * As documented in @see https://datatracker.ietf.org/doc/html/rfc8152#section-3
 * Checks if the CBOR supplied is a zero-length-map encoded as a zero-length-string
 */
export const isZeroLengthMap = (input: Buffer | Uint8Array): boolean => {
  let buffer;
  if (z.instanceof(Uint8Array).safeParse(buffer).success) {
    buffer = Buffer.from(input);
  } else {
    buffer = input;
  }
  return buffer.toString("hex") === ZERO_LENGTH_MAP_STRING_ENCODING;
};

/**
 * Decodes a COSE_Sign* structure to its underlying components
 *
 * TODO perhaps want to generalize to other COSE structures in future?
 *
 * @param payload
 */
export const decode = async (input: Uint8Array): Promise<DecodedPayloadResult> => {
  let decodedResult;
  try {
    decodedResult = await cbor.decodeFirst(input);
  } catch (ex) {
    throw new CoseError({
      type: CoseErrorTypes.DecodeError,
      message: "Fail to decode payload as CBOR",
      details: {
        rawError: ex,
      },
    });
  }

  let type;
  let tagged = false;
  if (decodedResult instanceof Tagged) {
    if (decodedResult.tag !== SignTag && decodedResult.tag !== Sign1Tag) {
      throw new CoseError({
        type: CoseErrorTypes.DecodeError,
        message: "Unexpected CBOR tag, '" + decodedResult.tag + "'",
        details: {},
      });
    }
    tagged = true;
    type = decodedResult.tag;
    decodedResult = decodedResult.value;
  }

  if (!Array.isArray(decodedResult)) {
    throw new CoseError({
      type: CoseErrorTypes.DecodeError,
      message: "Expecting decoded result to be an array",
      details: {},
    });
  }

  if (decodedResult.length !== 4) {
    throw new CoseError({
      type: CoseErrorTypes.DecodeError,
      message: "Expecting decoded result array length to be 4",
      details: {},
    });
  }

  if (type === undefined) {
    type = Array.isArray(decodedResult[3]) ? SignTag : Sign1Tag;
  }

  const [encodedProtectedHeaders, encodedUnProtectedHeaders, encodedPayload, signatureOrSigners] = decodedResult;

  if (!isByteArray(encodedPayload)) {
    throw new CoseError({
      type: CoseErrorTypes.DecodeError,
      message: "Expecting payload to be type binary",
      details: {},
    });
  }

  let payload;
  try {
    payload = cbor.decode(encodedPayload) ?? encodedPayload;
  } catch {
    // payload is not CBOR (e.g it is just binary) so just return the raw payload
  }

  if (type == Sign1Tag) {
    return {
      tagged,
      encodedProtectedHeaders: isZeroLengthMap(encodedProtectedHeaders) ? EMPTY_BUFFER : encodedProtectedHeaders,
      protectedHeaders: isZeroLengthMap(encodedProtectedHeaders) ? EMPTY_BUFFER : cbor.decode(encodedProtectedHeaders),
      encodedUnProtectedHeaders,
      unProtectedHeaders: encodedUnProtectedHeaders, // TODO
      payload,
      encodedPayload,
      signature: signatureOrSigners,
      structureType: CoseSignStructure.COSESign1,
    };
  }
  return {
    tagged,
    encodedProtectedHeaders,
    protectedHeaders: isZeroLengthMap(encodedProtectedHeaders) ? EMPTY_BUFFER : cbor.decode(encodedProtectedHeaders), // TODO
    encodedUnProtectedHeaders,
    unProtectedHeaders: encodedUnProtectedHeaders, // TODO
    payload,
    encodedPayload,
    signers: [
      {
        // TODO
        encodedProtectedHeaders,
        /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
        protectedHeaders: new Map<string | number, any>(),
        encodedUnProtectedHeaders,
        /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
        unProtectedHeaders: new Map<string | number, any>(),
        signature: signatureOrSigners,
      },
    ],
    structureType: CoseSignStructure.COSESign,
  };
};

/**
 * Fetch protected or unprotected header by tag (label), name or `CoseHeaderParameterEnum`
 * Gives priority to `protectedHeaders` over `unProtectedHeaders`
 * See https://datatracker.ietf.org/doc/html/rfc8152#section-3.1
 */
export const getHeader = (
  headers: {
    readonly unProtectedHeaders: NormalizedCoseHeaders;
    readonly protectedHeaders: NormalizedCoseHeaders;
  },
  header: number | string | CoseHeaderParameterEnum
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
): unknown => {
  let tag;
  let name;

  const parsedHeader = z.number().safeParse(header);
  if (parsedHeader.success) {
    tag = parsedHeader.data;
    name = CoseHeaderParametersReverseMap[tag];
  } else {
    name = header;
    tag = CoseHeaderParameters[name];
  }

  const result =
    headers.protectedHeaders.get(tag) ||
    headers.protectedHeaders.get(name) ||
    headers.unProtectedHeaders.get(tag) ||
    headers.unProtectedHeaders.get(name);

  return result;
};

/**
 * Fetch KID from protected or unprotected headers
 */
export const getKid = (decodedPayload: DecodedPayloadResult): Uint8Array => {
  return getHeader(decodedPayload, CoseHeaderParameterEnum.kid) as Uint8Array;
};
