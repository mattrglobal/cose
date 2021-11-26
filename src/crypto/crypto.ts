/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { Crypto } from "@peculiar/webcrypto";

/* eslint-disable-next-line @typescript-eslint/explicit-function-return-type */
export const getCryptoInstance = () => new Crypto();
