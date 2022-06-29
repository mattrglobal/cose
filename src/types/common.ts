/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Buffer } from "buffer";
import { z, ZodTypeAny } from "zod";

import { CoseError, CoseErrorTypes } from "../common/error";

export type ByteArray = Uint8Array | Buffer;

/**
 * @ignore
 */
export const isType =
  <T>(validator: ZodTypeAny) =>
  (value: unknown): value is T => {
    return validator.safeParse(value).success;
  };

/**
 * @ignore
 */
export const assertType =
  <T>(validator: ZodTypeAny, message: string) =>
  (data: unknown): data is T => {
    const result = validator.safeParse(data);
    if (!result.success) {
      throw new CoseError({ message, type: CoseErrorTypes.ValidationError, details: result.error });
    }
    return result.success;
  };

/**
 * @ignore
 */
export const isByteArray = isType<ByteArray>(z.union([z.instanceof(Uint8Array), z.instanceof(Buffer)]));
