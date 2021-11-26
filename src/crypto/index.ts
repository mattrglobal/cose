/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

import { CoseSignatureAlgorithmToWebCryptoAlgorithm } from "../types/Algorithms";

import { getCryptoInstance } from "./crypto";
import { JwkKty, JsonWebKeyPublic, JsonWebKey, assertJsonWebKeyPublic, assertJsonWebKeyPrivate } from "../types";
import { CoseError, CoseErrorTypes } from "../common/error";

const WEBCRYPTO_JWK_IDENTIFIER = "jwk";
const WEBCRYPTO_SIGNATURE_SIGN_KEY_USAGES: KeyUsage[] = ["sign"];
const WEBCRYPTO_SIGNATURE_VERIFY_KEY_USAGES: KeyUsage[] = ["verify"];

export const signData = async (coseAlgorithm: number, data: Uint8Array, key: JsonWebKey): Promise<Uint8Array> => {
  assertJsonWebKeyPrivate(key);

  const crypto = getCryptoInstance();

  const signingAlgorithm = CoseSignatureAlgorithmToWebCryptoAlgorithm[coseAlgorithm];

  let webCryptoAlgorithm;
  if (key.kty === JwkKty.OctetKeyPair || key.kty === JwkKty.EC) {
    webCryptoAlgorithm = {
      name: signingAlgorithm.name,
      namedCurve: key.crv,
    };
  }
  if (key.kty === JwkKty.RSA) {
    webCryptoAlgorithm = signingAlgorithm;
  }

  let importedKey;
  try {
    importedKey = await crypto.subtle.importKey(
      WEBCRYPTO_JWK_IDENTIFIER,
      key,
      webCryptoAlgorithm,
      false,
      WEBCRYPTO_SIGNATURE_SIGN_KEY_USAGES
    );
  } catch (ex) {
    throw new CoseError({
      type: CoseErrorTypes.CryptoError,
      message: "Failed to import key",
      details: {
        rawError: ex,
      },
    });
  }

  try {
    return new Uint8Array(await crypto.subtle.sign(signingAlgorithm, importedKey, data));
  } catch (ex) {
    throw new CoseError({
      type: CoseErrorTypes.CryptoError,
      message: "Failed to sign",
      details: {
        rawError: ex,
      },
    });
  }
};

export const verifyData = async (
  coseAlgorithm: number,
  data: Uint8Array,
  key: JsonWebKeyPublic,
  signature: Uint8Array
): Promise<boolean> => {
  const importingKey = assertJsonWebKeyPublic(key);

  const crypto = getCryptoInstance();

  const signingAlgorithm = CoseSignatureAlgorithmToWebCryptoAlgorithm[coseAlgorithm];

  // TODO need to check the type of the key being imported too making sure it matches the algorithm that is going to be used

  let webCryptoAlgorithm;
  if (key.kty === JwkKty.OctetKeyPair || key.kty === JwkKty.EC) {
    webCryptoAlgorithm = {
      name: signingAlgorithm.name,
      namedCurve: key.crv,
    };
  }
  if (key.kty === JwkKty.RSA) {
    webCryptoAlgorithm = signingAlgorithm;
  }

  let importedKey;
  try {
    importedKey = (await crypto.subtle.importKey(
      WEBCRYPTO_JWK_IDENTIFIER,
      importingKey,
      webCryptoAlgorithm,
      false,
      WEBCRYPTO_SIGNATURE_VERIFY_KEY_USAGES
    )) as CryptoKey;
  } catch (ex) {
    throw new CoseError({
      type: CoseErrorTypes.CryptoError,
      message: "Failed to import key",
      details: {
        rawError: ex,
      },
    });
  }

  try {
    return await crypto.subtle.verify(signingAlgorithm, importedKey, signature, data);
  } catch (ex) {
    throw new CoseError({
      type: CoseErrorTypes.CryptoError,
      message: "Failed to verify signature",
      details: {
        rawError: ex,
      },
    });
  }
};
