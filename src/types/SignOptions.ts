/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { z } from "zod";
import { MultiSignOptions, MultiSignOptionsValidator } from "./MultiSignOptions";
import { SingleSignOptions, SingleSignOptionsValidator } from "./SingleSignOptions";
import { assertType } from "./common";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * @ignore
 */
export type SignOptions = MultiSignOptions | SingleSignOptions;

/**
 * @ignore
 */
export const SignOptionsValidator = z.union([SingleSignOptionsValidator, MultiSignOptionsValidator]);

/**
 * @ignore
 */
export const assertSignOptions = assertType<SignOptions>(SignOptionsValidator, "Expected SignOptions");
