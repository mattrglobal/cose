/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { decode, EMPTY_BUFFER, getHeaderParameter, verifyPayload } from "./utilities";

import cbor from "./cbor";
import { verifyData } from "./crypto";
import { COSE_SIGN_1, CoseHeaderParameterEnum, VerifyOptions } from "./types";
import { VerificationResult } from "./types/VerificationResult";
import { assertVerifyOptions, Verifier } from "./types/VerifyOptions";
import { CoseSignStructure, DecodedSingleSignResult } from "./types/DecodedPayloadResult";
import { CoseError, CoseErrorTypes } from "./common/error";

const verifySingleSignature = async (options: {
  /* eslint-disable-next-line @typescript-eslint/no-explicit-any */
  additionalAuthenticatedData: any;
  decodedResult: DecodedSingleSignResult;
  verifier: Verifier;
}): Promise<VerificationResult> => {
  const { additionalAuthenticatedData } = options;
  const { decodedResult, verifier } = options;
  let { externalVerifier } = verifier;
  const { publicKey } = verifier;

  const { encodedProtectedHeaders, payload, encodedPayload, signature } = decodedResult;

  const SigStructure = [
    COSE_SIGN_1,
    encodedProtectedHeaders,
    additionalAuthenticatedData ?? EMPTY_BUFFER,
    encodedPayload,
  ];

  const algorithm = getHeaderParameter(CoseHeaderParameterEnum.alg, decodedResult);
  const encodedSignatureStructure = cbor.encodeCanonical(SigStructure);

  // TODO abstract to work with multiple verifiers
  // how does the kid VS array ordering

  let usingExternalVerifier = true;
  if (!externalVerifier && publicKey) {
    externalVerifier = (payload: Uint8Array, signature: Uint8Array): Promise<boolean> =>
      verifyData(algorithm, new Uint8Array(payload), publicKey, signature);
    usingExternalVerifier = false;
  }
  if (externalVerifier) {
    return {
      verified: await verifyPayload(
        externalVerifier,
        new Uint8Array(encodedSignatureStructure),
        new Uint8Array(signature),
        usingExternalVerifier
      ),
      payload,
    };
  }

  // Throw if there is neither an external verifier or public key supplied
  throw new CoseError({
    type: CoseErrorTypes.VerifyError,
    message: "Either verifier or key argument must be supplied",
    details: {},
  });
};

export const verifyMultipleSignatures = async (): Promise<VerificationResult> => {
  throw new Error("Not Implemented! Verifying COSE_Sign structures not supported");
};

export const verify = async (options: VerifyOptions): Promise<VerificationResult> => {
  assertVerifyOptions(options);

  const { verifier } = options;
  const { payload, additionalAuthenticatedData } = options;

  const decodedResult = await decode(payload);

  if (decodedResult.structureType === CoseSignStructure.COSESign1) {
    return await verifySingleSignature({
      additionalAuthenticatedData,
      decodedResult,
      verifier: verifier as Verifier,
    });
  } else {
    return await verifyMultipleSignatures();
  }
};
