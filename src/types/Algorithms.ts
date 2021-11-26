/*!
 * Copyright 2021 - MATTR Limited
 * All rights reserved
 * Confidential and proprietary
 */

/**
 * WEBCRYPTO identifier for Elliptic curve digital signature algorithm
 */
const WEBCRYPTO_ECDSA = "ECDSA";
/**
 * WEBCRYPTO identifier for Elliptic curve digital signature algorithm with Edwards curve
 */
const WEBCRYPTO_EDDSA = "eddsa";

/**
 * A map between a COSE signature algorithm
 * @see https://www.iana.org/assignments/cose/cose.xhtml
 *
 * To the equivalent WEBCRYPTO algorithm
 */
/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
export const CoseSignatureAlgorithmToWebCryptoAlgorithm: { [key: number]: any } = {
  [-7]: { name: WEBCRYPTO_ECDSA, hash: { name: "SHA-256" } },
  [-8]: { name: WEBCRYPTO_EDDSA },
  [-35]: { name: WEBCRYPTO_ECDSA, hash: { name: "SHA-384" } },
  [-36]: { name: WEBCRYPTO_ECDSA, hash: { name: "SHA-512" } },
  [-37]: { name: "RSA-PSS", saltLength: 128, hash: { name: "SHA-256" } },
  [-38]: { name: "RSA-PSS", saltLength: 128, hash: { name: "SHA-384" } },
  [-39]: { name: "RSA-PSS", saltLength: 128, hash: { name: "SHA-512" } },
};
