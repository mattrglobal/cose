/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

// TextDecoder Polyfill is required for React Native and browser support
global.TextDecoder = global.TextDecoder || require("@cto.af/textdecoder");
// BigInt Polyfill is required for React Native and browser support
global.BigInt = global.BigInt || require("bignumber.js");

export * from "./types";

export { sign } from "./sign";
export { verify } from "./verify";
export { decode, getHeaderParameter, getHeader, getKid } from "./utilities";
export { encodeCoseKey, decodeCoseKey } from "./coseKey";
export { CoseErrorTypes, CoseError, isCoseError } from "./common/error";
