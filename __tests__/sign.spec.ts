import { ed25519Jwk, p256Jwk, p384Jwk, p521Jwk, rsaJwk } from "./__fixtures__";

import { sign } from "../src/sign";
import { verify } from "../src/verify";
import { CoseSignatureAlgorithmEnum, JsonWebKeyPrivate } from "../src/types";
import { getCurrentNodeMajorVersion } from "./utilities";
import { signData } from "../src/crypto";
import { CoseErrorTypes } from "../src";
import { isMultiSignDecodedResult, isSingleSignDecodedResult } from "../src/types";
import cbor from "../src/cbor";

/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
describe("sign", () => {
  const nodeVersion = getCurrentNodeMajorVersion();
  const supportedAlgorithms: any = [
    {
      algorithmName: "ES256",
      algorithm: CoseSignatureAlgorithmEnum.ES256,
      key: p256Jwk,
      externalSigner: (payload: Uint8Array): Promise<Uint8Array> =>
        signData(CoseSignatureAlgorithmEnum.ES256, payload, p256Jwk),
    },
    {
      algorithmName: "ES384",
      algorithm: CoseSignatureAlgorithmEnum.ES384,
      key: p384Jwk,
      externalSigner: (payload: Uint8Array): Promise<Uint8Array> =>
        signData(CoseSignatureAlgorithmEnum.ES384, payload, p384Jwk),
    },
    {
      algorithmName: "ES512",
      algorithm: CoseSignatureAlgorithmEnum.ES512,
      key: p521Jwk,
      externalSigner: (payload: Uint8Array): Promise<Uint8Array> =>
        signData(CoseSignatureAlgorithmEnum.ES512, payload, p521Jwk),
    },
    {
      algorithmName: "PS256",
      algorithm: CoseSignatureAlgorithmEnum.PS256,
      key: rsaJwk,
      externalSigner: (payload: Uint8Array): Promise<Uint8Array> =>
        signData(CoseSignatureAlgorithmEnum.PS256, payload, rsaJwk),
    },
    {
      algorithmName: "PS384",
      algorithm: CoseSignatureAlgorithmEnum.PS384,
      key: rsaJwk,
      externalSigner: (payload: Uint8Array): Promise<Uint8Array> =>
        signData(CoseSignatureAlgorithmEnum.PS384, payload, rsaJwk),
    },
    {
      algorithmName: "PS512",
      algorithm: CoseSignatureAlgorithmEnum.PS512,
      key: rsaJwk,
      externalSigner: (payload: Uint8Array): Promise<Uint8Array> =>
        signData(CoseSignatureAlgorithmEnum.PS512, payload, rsaJwk),
    },
  ];

  if (nodeVersion && nodeVersion >= 14) {
    supportedAlgorithms.push({
      algorithmName: "EdDSA",
      algorithm: CoseSignatureAlgorithmEnum.EdDSA,
      key: ed25519Jwk,
      externalSigner: (payload: Uint8Array): Promise<Uint8Array> =>
        signData(CoseSignatureAlgorithmEnum.EdDSA, payload, ed25519Jwk as any),
    });
  }

  describe("multi-sign", () => {
    it("should sign string payload", async () => {
      const result = await sign({
        signers: [
          {
            algorithm: CoseSignatureAlgorithmEnum.ES256,
            privateKey: p256Jwk,
          },
        ],
        payload: "This is a payload",
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(96);
    });

    it("should sign string payload and produce MultiSignDecodedResult with skipEncodingResult", async () => {
      const result = await sign({
        signers: [
          {
            algorithm: CoseSignatureAlgorithmEnum.ES256,
            privateKey: p256Jwk,
          },
        ],
        skipEncodingResult: true,
        payload: "This is a payload",
      });

      expect(isMultiSignDecodedResult(result)).toBeTruthy();
    });

    it("should sign number payload", async () => {
      const result = await sign({
        signers: [
          {
            algorithm: CoseSignatureAlgorithmEnum.ES256,
            privateKey: p256Jwk,
          },
        ],
        payload: 101,
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(80);
    });

    it("should sign boolean payload", async () => {
      const result = await sign({
        signers: [
          {
            algorithm: CoseSignatureAlgorithmEnum.ES256,
            privateKey: p256Jwk,
          },
        ],
        payload: false,
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(79);
    });

    it("should sign object payload", async () => {
      const result = await sign({
        signers: [
          {
            algorithm: CoseSignatureAlgorithmEnum.ES256,
            privateKey: p256Jwk,
          },
        ],
        payload: {
          test: "attribute",
          isTest: true,
        },
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(103);
    });

    it("should sign array payload", async () => {
      const result = await sign({
        signers: [
          {
            algorithm: CoseSignatureAlgorithmEnum.ES256,
            privateKey: p256Jwk,
          },
        ],
        payload: [
          {
            test: "attribute",
            isTest: true,
          },
          {
            test: "attribute1",
            isTest: false,
          },
        ],
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(129);
    });

    it("should sign map payload", async () => {
      const result = await sign({
        signers: [
          {
            algorithm: CoseSignatureAlgorithmEnum.ES256,
            privateKey: p256Jwk,
          },
        ],
        payload: new Map([
          ["key1", "value1"],
          ["key2", "value2"],
        ]),
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(104);
    });

    it("should fail without algorithm", async () => {
      await expect(
        sign({
          signers: [
            {
              privateKey: p256Jwk,
            },
          ],
          payload: "This is a payload",
        } as any)
      ).rejects.toThrowError("Expected SignOptions");
    });

    it("should fail with un-recognized algorithm", async () => {
      await expect(
        sign({
          signers: [
            {
              algorithm: -999,
              privateKey: p256Jwk,
            },
          ],
          payload: "This is a payload",
        } as any)
      ).rejects.toThrowError("Expected SignOptions");
    });

    it("should fail if neither key nor signer function supplied", async () => {
      await expect(
        sign({
          signers: [
            {
              algorithm: CoseSignatureAlgorithmEnum.ES256,
            },
          ],
          payload: "This is a payload",
        })
      ).rejects.toMatchObject({
        type: CoseErrorTypes.SignError,
        message: "Either signer or key argument must be supplied",
      });
    });
  });

  describe("sign1", () => {
    supportedAlgorithms.forEach((value: any) => {
      it(`should successfully round trip sign-verify with ${value.algorithmName} algorithm`, async () => {
        const result = await sign({
          privateKey: value.key,
          payload: "This is a payload",
          algorithm: value.algorithm,
        });

        const verificationResult = await verify({
          payload: result,
          verifier: {
            publicKey: value.key,
          },
        });

        expect(verificationResult.verified).toBeTruthy();
      });

      it(`should successfully round trip sign-verify with ${value.algorithmName} algorithm and skipEncodingResult`, async () => {
        const result = await sign({
          privateKey: value.key,
          payload: "This is a payload",
          algorithm: value.algorithm,
          skipEncodingResult: true,
        });

        expect(isSingleSignDecodedResult(result)).toBeTruthy();

        const encodedResult = new Uint8Array(cbor.encodeCanonical(result));
        const verificationResult = await verify({
          payload: encodedResult,
          verifier: {
            publicKey: value.key,
          },
        });

        expect(verificationResult.verified).toBeTruthy();
      });

      it(`should successfully round trip sign-verify with ${value.algorithmName} algorithm using external signer`, async () => {
        const result = await sign({
          externalSigner: value.externalSigner,
          payload: "This is a payload",
          algorithm: value.algorithm,
        });

        const verificationResult = await verify({
          payload: result,
          verifier: {
            publicKey: value.key,
          },
        });

        expect(verificationResult.verified).toBeTruthy();
      });
    });

    it("should sign string payload", async () => {
      const result = await sign({
        privateKey: p256Jwk,
        payload: "This is a payload",
        algorithm: CoseSignatureAlgorithmEnum.ES256,
      });

      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(92);
    });

    it("should sign number payload", async () => {
      const result = await sign({
        privateKey: p256Jwk,
        payload: 101,
        algorithm: CoseSignatureAlgorithmEnum.ES256,
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(76);
    });

    it("should sign boolean payload", async () => {
      const result = await sign({
        privateKey: p256Jwk,
        payload: false,
        algorithm: CoseSignatureAlgorithmEnum.ES256,
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(75);
    });

    it("should sign object payload", async () => {
      const result = await sign({
        privateKey: p256Jwk,
        payload: {
          test: "attribute",
          isTest: true,
        },
        algorithm: CoseSignatureAlgorithmEnum.ES256,
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(99);
    });

    it("should sign array payload", async () => {
      const result = await sign({
        privateKey: p256Jwk,
        payload: [
          {
            test: "attribute",
            isTest: true,
          },
          {
            test: "attribute1",
            isTest: false,
          },
        ],
        algorithm: CoseSignatureAlgorithmEnum.ES256,
      });
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toEqual(125);
    });

    it("should fail if payload is not binary and skipEncodingPayload = true", async () => {
      await expect(
        sign({
          signers: [
            {
              algorithm: CoseSignatureAlgorithmEnum.ES256,
              privateKey: p256Jwk,
            },
          ],
          skipEncodingPayload: true,
          payload: {
            test: "attribute",
            isTest: true,
          },
        })
      ).rejects.toMatchObject({
        type: CoseErrorTypes.SignError,
        message: "Expected options.payload type to be binary if skipEncodingPayload = true",
      });
    });

    it("should fail without algorithm", async () => {
      await expect(
        sign({
          key: p256Jwk,
          payload: "This is a payload",
        } as any)
      ).rejects.toThrowError("Expected SignOptions");
    });

    it("should fail with un-recognized algorithm", async () => {
      await expect(
        sign({
          algorithm: -999,
          key: p256Jwk,
          payload: "This is a payload",
        } as any)
      ).rejects.toThrowError("Expected SignOptions");
    });

    it("should fail if neither key nor signer function supplied", async () => {
      await expect(
        sign({
          algorithm: CoseSignatureAlgorithmEnum.ES256,
          payload: "This is a payload",
        })
      ).rejects.toMatchObject({
        type: CoseErrorTypes.SignError,
        message: "Either signer or key argument must be supplied",
      });
    });

    it("should fail with invalid key", async () => {
      await expect(
        sign({
          privateKey: {} as JsonWebKeyPrivate,
          payload: "This is a payload",
          algorithm: CoseSignatureAlgorithmEnum.ES256,
        })
      ).rejects.toThrowError("Expected SignOptions");
    });

    it("should fail without payload", async () => {
      await expect(
        sign({
          privateKey: p256Jwk,
          algorithm: CoseSignatureAlgorithmEnum.ES256,
        } as any)
      ).rejects.toThrowError("Expected SignOptions");
    });

    it("should fail when only supplied with public key", async () => {
      const key = { ...p256Jwk, d: undefined };

      await expect(
        sign({
          privateKey: key,
          payload: "This is a payload",
          algorithm: CoseSignatureAlgorithmEnum.ES256,
        })
      ).rejects.toThrowError("Expected SignOptions");
    });

    it("should fail when signer function supplied failed", async () => {
      await expect(
        sign({
          externalSigner: (_: Uint8Array) => {
            throw new Error("Whoa something un-expected happened");
          },
          payload: "This is a payload",
          algorithm: CoseSignatureAlgorithmEnum.ES256,
        })
      ).rejects.toMatchObject({
        type: CoseErrorTypes.ExternalSignerFunctionError,
        message: "Calling externally supplied signer function failed",
        details: {
          rawError: new Error("Whoa something un-expected happened"),
        },
      });
    });
  });
});
