import { ed25519Jwk, p256Jwk, p384Jwk, p521Jwk, rsaJwk } from "./__fixtures__";

import { signData, verifyData } from "../src/crypto";
import { CoseSignatureAlgorithmEnum } from "../src/types";
import { getCurrentNodeMajorVersion } from "./utilities";

describe("crypto", () => {
  const nodeVersion = getCurrentNodeMajorVersion();
  const testData = Buffer.from("testData");

  describe("sign", () => {
    it.each([
      ["ES256", CoseSignatureAlgorithmEnum.ES256, p256Jwk, 64],
      ["ES384", CoseSignatureAlgorithmEnum.ES384, p384Jwk, 96],
      ["ES512", CoseSignatureAlgorithmEnum.ES512, p521Jwk, 132],
      ["PS256", CoseSignatureAlgorithmEnum.PS256, rsaJwk, 256],
      ["PS384", CoseSignatureAlgorithmEnum.PS384, rsaJwk, 256],
      ["PS512", CoseSignatureAlgorithmEnum.PS512, rsaJwk, 256],
    ])(`should sign  data with algorithm %s`, async (_algorithm, coseAlgorithm, publicKey, length) => {
      const signPayload = await signData(coseAlgorithm, testData, publicKey);
      expect(signPayload).toBeDefined();
      expect(signPayload.byteLength).toEqual(length);
    });

    if (nodeVersion && nodeVersion >= 14) {
      it(`should sign data with algorithm EdDSA`, async () => {
        const coseAlgorithm = CoseSignatureAlgorithmEnum.EdDSA;
        const publicKey = ed25519Jwk;
        const signPayload = await signData(coseAlgorithm, testData, publicKey);
        expect(signPayload).toBeDefined();
        expect(signPayload.byteLength).toEqual(64);
      });
    }
  });

  describe("verify", () => {
    it.each([
      ["ES256", CoseSignatureAlgorithmEnum.ES256, p256Jwk],
      ["ES384", CoseSignatureAlgorithmEnum.ES384, p384Jwk],
      ["ES512", CoseSignatureAlgorithmEnum.ES512, p521Jwk],
      ["PS256", CoseSignatureAlgorithmEnum.PS256, rsaJwk],
      ["PS384", CoseSignatureAlgorithmEnum.PS384, rsaJwk],
      ["PS512", CoseSignatureAlgorithmEnum.PS512, rsaJwk],
    ])(`should sign and verify data with algorithm %s`, async (_algorithm, coseAlgorithm, publicKey) => {
      const signPayload = await signData(coseAlgorithm, testData, publicKey);
      const verifyResult = await verifyData(coseAlgorithm, testData, publicKey, signPayload);
      expect(verifyResult).toBeTruthy();
    });

    if (nodeVersion && nodeVersion >= 14) {
      it(`should sign data with algorithm EdDSA`, async () => {
        const coseAlgorithm = CoseSignatureAlgorithmEnum.EdDSA;
        const publicKey = ed25519Jwk;
        const signPayload = await signData(coseAlgorithm, testData, publicKey);
        const verifyResult = await verifyData(coseAlgorithm, testData, publicKey, signPayload);
        expect(verifyResult).toBeTruthy();
      });
    }
  });
});
