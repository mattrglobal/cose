/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { z } from "zod";
import { isType } from "./common";
import { NormalizedCoseHeaders } from "./NormalizedCoseHeaders";

export type MultiSignSignature = [Buffer, NormalizedCoseHeaders | undefined, Buffer];
export type MultiSignDecodedResult = [Buffer, NormalizedCoseHeaders | undefined, unknown, MultiSignSignature[]];

export const MultiSignSignatureValidator = z.tuple([
  z.instanceof(Buffer),
  z.map(z.union([z.string(), z.number()]), z.any()).optional(),
  z.instanceof(Buffer),
]);

export const MultiSignDecodedResultValidator = z.tuple([
  z.instanceof(Buffer),
  z.map(z.union([z.string(), z.number()]), z.any()).optional(),
  z.any(),
  z.array(MultiSignSignatureValidator),
]);

/**
 * @ignore
 */
export const isMultiSignDecodedResult = isType<MultiSignDecodedResult>(MultiSignDecodedResultValidator);
