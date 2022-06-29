/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { convertEnumToObj, convertEnumToReverseMapObj } from "./utilities";

/**
 * A list of supported COSE Key Type Parameters for Elliptic Curve based keys EC2 and OKP
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export enum CoseEcKeyTypeParameterEnum {
  crv = -1,
  x = -2,
  y = -3,
  d = -4,
}

/**
 * A list of supported COSE Key Type Parameters for Elliptic Curve based keys EC2 and OKP
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseEcKeyTypeParameters: { [key: string]: number } = convertEnumToObj(CoseEcKeyTypeParameterEnum);

/**
 * A list of supported COSE Key Type Parameters for Elliptic Curve based keys EC2 and OKP
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseEcKeyTypeParametersReverseMap: { [key: number]: string } =
  convertEnumToReverseMapObj(CoseEcKeyTypeParameterEnum);
