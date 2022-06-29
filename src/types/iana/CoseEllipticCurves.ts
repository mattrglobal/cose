/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { convertEnumToObj, convertEnumToReverseMapObj } from "./utilities";

/**
 * A list of supported COSE Elliptic Curves
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export enum CoseEllipticCurveEnum {
  P256 = 1,
  P384 = 2,
  P521 = 3,
  X25519 = 4,
  X448 = 5,
  Ed25519 = 6,
  Ed448 = 7,
  secp256k1 = 8,
}

/**
 * A list of supported COSE Elliptic Curves
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseEllipticCurves: { [key: string]: number } = convertEnumToObj(CoseEllipticCurveEnum);

/**
 * A list of supported COSE Elliptic Curves
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseEllipticCurvesReverseMap: { [key: number]: string } =
  convertEnumToReverseMapObj(CoseEllipticCurveEnum);
