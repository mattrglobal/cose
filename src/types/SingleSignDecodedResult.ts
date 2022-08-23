/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { NormalizedCoseHeaders } from "./NormalizedCoseHeaders";
import { z } from "zod";
import { isType } from "./common";

export type SingleSignDecodedResult = [Buffer, NormalizedCoseHeaders | undefined, unknown, Buffer];

export const SingleSignDecodedResultValidator = z.tuple([
  z.instanceof(Buffer),
  z.map(z.union([z.string(), z.number()]), z.any()).optional(),
  z.any(),
  z.instanceof(Buffer),
]);

/**
 * @ignore
 */
export const isSingleSignDecodedResult = isType<SingleSignDecodedResult>(SingleSignDecodedResultValidator);
