/*!
 * Copyright 2019 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { z } from "zod";
import { assertType } from "./common";
import { convertEnumToObj, convertEnumToReverseMapObj } from "./iana/utilities";

/**
 * @ignore
 */
export enum JwkKty {
  OctetKeyPair = "OKP",
  EC = "EC",
  RSA = "RSA",
}

/**
 * @ignore
 */
enum JwkKtyToCoseKeyTypeEnum {
  OKP = 1,
  EC = 2,
  RSA = 3,
}

/**
 * @ignore
 */
export const JwkKtyToCoseKeyTypeConversionMap: { [key: string]: number } = convertEnumToObj(JwkKtyToCoseKeyTypeEnum);

/**
 * @ignore
 */
export const CoseKeyTypeToJwkKtyConversionMap: { [key: number]: string } =
  convertEnumToReverseMapObj(JwkKtyToCoseKeyTypeEnum);

/**
 * @ignore
 */
export interface JwkEcPublic {
  readonly kty: JwkKty.EC;
  readonly crv: JwkEcCurve;
  readonly x?: string;
  readonly y?: string;
  readonly kid?: string;
}

/**
 * @ignore
 */
export interface JwkEc extends JwkEcPublic {
  readonly d?: string;
}

/**
 * @ignore
 */
export interface JwkEcPrivate extends JwkEcPublic {
  readonly d: string;
}

/**
 * @ignore
 */
export interface JwkOctetKeyPairPublic {
  readonly kty: JwkKty.OctetKeyPair;
  readonly crv: string;
  readonly x?: string;
  readonly y?: string;
  readonly kid?: string;
}

/**
 * @ignore
 */
export interface JwkOctetKeyPair extends JwkOctetKeyPairPublic {
  readonly d?: string;
}

/**
 * @ignore
 */
export interface JwkOctetKeyPairPrivate extends JwkOctetKeyPairPublic {
  readonly d: string;
}

/**
 * @ignore
 */
export interface JwkRsaPublic {
  readonly kty: JwkKty.RSA;
  readonly e: string;
  readonly n: string;
}

/**
 * @ignore
 */
export interface JwkRsa extends JwkRsaPublic {
  readonly d?: string;
  readonly p?: string;
  readonly q?: string;
  readonly dp?: string;
  readonly dq?: string;
  readonly qi?: string;
}

/**
 * @ignore
 */
export interface JwkRsaPrivate extends JwkRsaPublic {
  readonly d: string;
  readonly p: string;
  readonly q: string;
  readonly dp: string;
  readonly dq: string;
  readonly qi: string;
}

/**
 * @ignore
 */
export type JsonWebKeyPublic = JwkOctetKeyPairPublic | JwkEcPublic | JwkRsaPublic;

/**
 * @ignore
 */
export type JsonWebKey = JwkOctetKeyPair | JwkEc | JwkRsa;

/**
 * @ignore
 */
export type JsonWebKeyPrivate = JwkOctetKeyPair | JwkEc | JwkRsa;

/**
 * @ignore
 */
export enum JwkEcCurve {
  P256 = "P-256",
  P384 = "P-384",
  P521 = "P-521",
}

/**
 * @ignore
 */
export enum JwkOctetKeyPairCurve {
  Ed25519 = "Ed25519",
  Ed448 = "Ed448",
  X25519 = "X25519",
  X448 = "X448",
}

/**
 * @ignore
 */
enum JwkCrvToCoseKeyCurveEnum {
  // EC Curve
  "P-256" = 1,
  "P-384" = 2,
  "P-521" = 3,
  // Octet key pair
  "Ed25519" = 6,
  "Ed448" = 7,
  "X25519" = 4,
  "X448" = 5,
}

/**
 * @ignore
 */
export const JwkCrvToCoseKeyCurveConversionMap: { [key: string]: number } = convertEnumToObj(JwkCrvToCoseKeyCurveEnum);

/**
 * @ignore
 */
export const CoseKeyCurveToJwkCrvConversionMap: { [key: number]: string } =
  convertEnumToReverseMapObj(JwkCrvToCoseKeyCurveEnum);

/**
 * @ignore
 */
export const JwkEcPublicValidator = z.object({
  kty: z.literal(JwkKty.EC),
  crv: z.nativeEnum(JwkEcCurve),
  x: z.string().optional(),
  y: z.string().optional(),
  kid: z.string().optional(),
});

/**
 * @ignore
 */
export const JwkEcValidator = z.object({
  kty: z.literal(JwkKty.EC),
  crv: z.nativeEnum(JwkEcCurve),
  d: z.string().optional(),
  x: z.string().optional(),
  y: z.string().optional(),
  kid: z.string().optional(),
});

/**
 * @ignore
 */
export const JwkEcPrivateValidator = z.object({
  kty: z.literal(JwkKty.EC),
  crv: z.nativeEnum(JwkEcCurve),
  d: z.string(),
  x: z.string().optional(),
  y: z.string().optional(),
  kid: z.string().optional(),
});

/**
 * @ignore
 */
export const JwkOctetKeyPairPublicValidator = z.object({
  kty: z.literal(JwkKty.OctetKeyPair),
  crv: z.nativeEnum(JwkOctetKeyPairCurve),
  x: z.string().optional(),
  y: z.string().optional(),
  kid: z.string().optional(),
});

/**
 * @ignore
 */
export const JwkOctetKeyPairValidator = z.object({
  kty: z.literal(JwkKty.OctetKeyPair),
  crv: z.nativeEnum(JwkOctetKeyPairCurve),
  d: z.string().optional(),
  x: z.string().optional(),
  y: z.string().optional(),
  kid: z.string().optional(),
});

/**
 * @ignore
 */
export const JwkOctetKeyPairPrivateValidator = z.object({
  kty: z.literal(JwkKty.OctetKeyPair),
  crv: z.nativeEnum(JwkOctetKeyPairCurve),
  d: z.string(),
  x: z.string().optional(),
  y: z.string().optional(),
  kid: z.string().optional(),
});

/**
 * @ignore
 */
export const JwkRsaPublicValidator = z.object({
  kty: z.literal(JwkKty.RSA),
  e: z.string(),
  n: z.string(),
});

/**
 * @ignore
 */
export const JwkRsaValidator = z.object({
  kty: z.literal(JwkKty.RSA),
  e: z.string(),
  n: z.string(),
  d: z.string().optional(),
  p: z.string().optional(),
  q: z.string().optional(),
  dp: z.string().optional(),
  dq: z.string().optional(),
  qi: z.string().optional(),
});

/**
 * @ignore
 */
export const JwkRsaPrivateValidator = z.object({
  kty: z.literal(JwkKty.RSA),
  e: z.string(),
  n: z.string(),
  d: z.string(),
  p: z.string(),
  q: z.string(),
  dp: z.string(),
  dq: z.string(),
  qi: z.string(),
});

/**
 * @ignore
 */
export const JsonWebKeyPublicValidator = z.union([
  JwkEcPublicValidator,
  JwkOctetKeyPairPublicValidator,
  JwkRsaPublicValidator,
]);

/**
 * @ignore
 */
export const JsonWebKeyValidator = z.union([JwkEcValidator, JwkOctetKeyPairValidator, JwkRsaValidator]);

/**
 * @ignore
 */
export const JsonWebKeyPrivateValidator = z.union([
  JwkEcPrivateValidator,
  JwkOctetKeyPairPrivateValidator,
  JwkRsaPrivateValidator,
]);

/**
 * @ignore
 */
export const assertJwkEc = assertType<JwkEc>(JwkEcValidator, "Expected JwkEc");

/**
 * @ignore
 */
export const assertJwkOctetKeyPair = assertType<JwkOctetKeyPair>(JwkOctetKeyPairValidator, "Expected JwkOctetKeyPair");

/**
 * @ignore
 */
export const assertJwkRsa = assertType<JwkRsa>(JwkRsaValidator, "Expected JwkRsa");

/**
 * @ignore
 */
export const assertJwkRsaPrivate = assertType<JwkRsaPrivate>(JwkRsaPrivateValidator, "Expected JwkRsaPrivate");

/**
 * @ignore
 */
export const assertJsonWebKey = assertType<JsonWebKey>(JsonWebKeyValidator, "Expected JsonWebKey");

/**
 * @ignore
 */
export const assertJsonWebKeyPublic = (key: JsonWebKeyPrivate): JsonWebKeyPublic => {
  const copiedKey = { ...key };

  // TODO this should be done more generally via what attributes are defined on the concerned interface
  if ((copiedKey.kty === JwkKty.OctetKeyPair || key.kty === JwkKty.EC) && copiedKey.d) {
    delete copiedKey.d;
  }

  if (copiedKey.kty === JwkKty.RSA) {
    delete copiedKey.p;
    delete copiedKey.q;
    delete copiedKey.d;
  }

  assertType<JsonWebKeyPublic>(JsonWebKeyPublicValidator, "Expected JsonWebKeyPublic");

  return copiedKey;
};

/**
 * @ignore
 */
export const assertJsonWebKeyPrivate = assertType<JsonWebKeyPrivate>(
  JsonWebKeyPrivateValidator,
  "Expected JsonWebKeyPrivate"
);
