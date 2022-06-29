/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { convertEnumToObj, convertEnumToReverseMapObj } from "./utilities";

/**
 * A list of supported COSE Header Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export enum CoseHeaderParameterEnum {
  alg = 1,
  ctyp = 3,
  kid = 4,
  IV = 5,
  PartialIV = 6,
  countersignature = 7,
  coutnersignature0 = 9,
  kidcontext = 10,
  x5bag = 32,
  x5chain = 33,
  x5u = 35,
}

/**
 * A list of supported COSE Header Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseHeaderParameters: { [key: string]: number } = convertEnumToObj(CoseHeaderParameterEnum);

/**
 * A list of supported COSE Header Parameters
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 */
export const CoseHeaderParametersReverseMap: { [key: number]: string } =
  convertEnumToReverseMapObj(CoseHeaderParameterEnum);
