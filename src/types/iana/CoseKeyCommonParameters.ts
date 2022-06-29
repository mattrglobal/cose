/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { convertEnumToObj, convertEnumToReverseMapObj } from "./utilities";

/**
 * A list of supported COSE Key Common Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export enum CoseKeyCommonParameterEnum {
  kty = 1,
  kid = 2,
  alg = 3,
  key_ops = 4,
  BaseIV = 5,
}

/**
 * A list of supported COSE Key Common Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseKeyCommonParameters: { [key: string]: number } = convertEnumToObj(CoseKeyCommonParameterEnum);

/**
 * A list of supported COSE Key Common Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseKeyCommonParametersReverseMap: { [key: number]: string } =
  convertEnumToReverseMapObj(CoseKeyCommonParameterEnum);
