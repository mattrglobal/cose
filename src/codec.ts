/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Buffer } from "buffer";
import * as base64 from "@stablelib/base64";

export const bytesToString = (bytes: Uint8Array): string => Buffer.from(bytes).toString();

export const stringToBytes = (str: string): Uint8Array => Uint8Array.from(Buffer.from(str, "utf-8"));

export const base64UrlEncodeNoPadding = (data: Uint8Array): string => {
  const urlSafeWithPadding = base64.encodeURLSafe(data);
  // removes urlSafe padding
  return urlSafeWithPadding.split("=")[0];
};

export const base64UrlDecodeNoPadding = (str: string): Uint8Array => {
  /**
   * following implementation in RFC 7515 Appendix C
   * note: case 1 is not possible because that's malformed base64url
   *
   * @see https://tools.ietf.org/html/rfc7515#appendix-C
   */
  switch (str.length % 4) {
    case 0:
      return base64.decodeURLSafe(str);
    case 2:
      return base64.decodeURLSafe(str + "==");
    case 3:
      return base64.decodeURLSafe(str + "=");
    default:
      throw Error("Illegal base64url string");
  }
};
