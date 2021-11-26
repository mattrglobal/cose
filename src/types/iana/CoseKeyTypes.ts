/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { convertEnumToObj, convertEnumToReverseMapObj } from "./utilities";

/**
 * A list of supported COSE Key Types
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export enum CoseKeyTypeEnum {
  OKP = 1,
  EC2 = 2,
  RSA = 3,
  Symmetric = 4,
  Reserved = 0,
}

/**
 * A list of supported COSE Key Types
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseKeyTypes: { [key: string]: number } = convertEnumToObj(CoseKeyTypeEnum);

/**
 * A list of supported COSE Key Types
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseKeyTypesReverseMap: { [key: number]: string } = convertEnumToReverseMapObj(CoseKeyTypeEnum);
