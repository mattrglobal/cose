/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { CoseError, CoseErrorTypes } from "../common/error";

/* eslint-disable-next-line @typescript-eslint/explicit-function-return-type */
export const getCryptoInstance = () => {
  throw new CoseError({
    type: CoseErrorTypes.NotImplementedError,
    message: "Crypto not available in react native, supply implementation externally",
    details: {},
  });
};
