/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { convertEnumToObj, convertEnumToReverseMapObj } from "./utilities";

/**
 * A list of supported COSE Algorithms for usage with COSE_Sign* structures
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export enum CoseSignatureAlgorithmEnum {
  ES256 = -7,
  EdDSA = -8,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
}

/**
 * A list of supported COSE Algorithms for usage with COSE_Sign* structures
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseSignatureAlgorithms: { [key: string]: number } = convertEnumToObj(CoseSignatureAlgorithmEnum);

/**
 * A list of supported COSE Algorithms for usage with COSE_Sign* structures
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseSignatureAlgorithmsReverseMap: { [key: number]: string } =
  convertEnumToReverseMapObj(CoseSignatureAlgorithmEnum);
