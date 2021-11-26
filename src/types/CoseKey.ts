/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { z } from "zod";
import { isType } from "./common";

/**
 * @ignore
 */
export type CoseKey = Uint8Array;

/**
 * @ignore
 */
export const isCoseKey = isType<Uint8Array>(z.instanceof(Uint8Array));

/**
 * @ignore
 */
/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
export const assertCoseKey = (options: any): void => {
  if (!isCoseKey(options)) {
    throw new Error("Expected CoseKey");
  }
};
