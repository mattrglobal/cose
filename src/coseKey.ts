/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import cbor from "./cbor";

import {
  CoseEcKeyTypeParametersReverseMap,
  CoseKey,
  assertCoseKey,
  CoseKeyCommonParametersReverseMap,
  assertJsonWebKey,
  JsonWebKey,
  ConverterMap,
  CoseKeyCurveToJwkCrvConversionMap,
  CoseKeyTypeToJwkKtyConversionMap,
  JwkCrvToCoseKeyCurveConversionMap,
  JwkKtyToCoseKeyTypeConversionMap,
  CoseHeaders,
  NormalizedCoseHeaders,
  CoseKeyCommonParameters,
  CoseEcKeyTypeParameters,
} from "./types";
import { bytesToString, stringToBytes, base64UrlDecodeNoPadding, base64UrlEncodeNoPadding } from "./codec";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * @ignore
 */
const CoseToJwkParameterConverterMap: ConverterMap = {
  kid: (value: string) => {
    return stringToBytes(value);
  },
  x: (value: string) => {
    return base64UrlDecodeNoPadding(value);
  },
  y: (value: string) => {
    return base64UrlDecodeNoPadding(value);
  },
  d: (value: string) => {
    return base64UrlDecodeNoPadding(value);
  },
  crv: (value: string) => {
    return JwkCrvToCoseKeyCurveConversionMap[value] ?? value;
  },
  kty: (value: string) => {
    return JwkKtyToCoseKeyTypeConversionMap[value] ?? value;
  },
};

/**
 * @ignore
 */
const JwkToCoseParameterConverterMap: ConverterMap = {
  kid: (value: Uint8Array) => {
    return bytesToString(value);
  },
  x: (value: Uint8Array) => {
    return base64UrlEncodeNoPadding(value);
  },
  y: (value: Uint8Array) => {
    return base64UrlEncodeNoPadding(value);
  },
  d: (value: Uint8Array) => {
    return base64UrlEncodeNoPadding(value);
  },
  crv: (value: number) => {
    return CoseKeyCurveToJwkCrvConversionMap[value] ?? value;
  },
  kty: (value: number) => {
    return CoseKeyTypeToJwkKtyConversionMap[value] ?? value;
  },
};

/**
 * @ignore
 */
const convertJwkParametersToCoseKeyParameters = (headers: CoseHeaders): NormalizedCoseHeaders => {
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  const result = new Map<number | string, any>();
  for (const param in headers) {
    let coseTag = CoseKeyCommonParameters[param];

    if (!coseTag) {
      coseTag = CoseEcKeyTypeParameters[param];
    }

    let value = headers[param];
    if (CoseToJwkParameterConverterMap[param]) {
      value = CoseToJwkParameterConverterMap[param](headers[param]);
    }

    result.set(coseTag ?? param, value);
  }
  return result;
};

/**
 * @ignore
 */
export const encodeCoseKey = (request: JsonWebKey): CoseKey => {
  assertJsonWebKey(request);

  const convertedKey = convertJwkParametersToCoseKeyParameters(request);

  // TODO review Uint8Arrays are automatically being tagged with 64 because of node-cbor

  return new Uint8Array(cbor.encode(convertedKey));
};

/**
 * @ignore
 */
export const decodeCoseKey = (key: CoseKey): JsonWebKey => {
  assertCoseKey(key);

  const decodedCoseKey = cbor.decode(key);

  const result: { [key: string]: any } = {};
  decodedCoseKey.forEach((value: any, key: number | string) => {
    const mappedField = CoseEcKeyTypeParametersReverseMap[key as any] ?? CoseKeyCommonParametersReverseMap[key as any];

    let convertedValue;
    if (JwkToCoseParameterConverterMap[mappedField]) {
      convertedValue = JwkToCoseParameterConverterMap[mappedField](value);
    }

    if (mappedField) {
      result[mappedField] = convertedValue;
    }
  });

  assertJsonWebKey(result as any);

  return result as JsonWebKey;
};
