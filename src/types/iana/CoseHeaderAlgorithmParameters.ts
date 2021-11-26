/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { convertEnumToObj, convertEnumToReverseMapObj } from "./utilities";

/**
 * A list of supported COSE Header Algorithm Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export enum CoseHeaderAlgorithmParameterEnum {
  PartyVother = -26,
  PartyVnonce = -25,
  PartyVidentity = -24,
  PartyUother = -23,
  PartyUnonce = -22,
  PartyUidentity = -21,
  salt = -20,
  statickeyid = -3,
  statickey = -2,
  ephemeralkey = -1,
}

/**
 * A list of supported COSE Header Algorithm Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseHeaderAlgorithmParameters: { [key: string]: number } = convertEnumToObj(
  CoseHeaderAlgorithmParameterEnum
);

/**
 * A list of supported COSE Header Algorithm Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseHeaderAlgorithmParametersReverseMap: { [key: number]: string } = convertEnumToReverseMapObj(
  CoseHeaderAlgorithmParameterEnum
);
