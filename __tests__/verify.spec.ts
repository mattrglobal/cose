import { p256Jwk, verificationFixtures } from "./__fixtures__";

import cbor, { Tagged } from "../src/cbor";

import { verify } from "../src/verify";
import { VerifierFunction } from "../src/types/VerifyOptions";
import { verifyData } from "../src/crypto";
import { CoseSignatureAlgorithmEnum } from "../src/types";
import { CoseErrorTypes } from "../src";

/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
describe("verify1", () => {
  verificationFixtures.forEach((item) => {
    it(`should pass case ${item.valueType}`, async () => {
      const result = await verify({
        payload: new Uint8Array(Buffer.from(item.fixture, "hex")),
        verifier: {
          publicKey: p256Jwk,
        },
      });

      expect(result.verified).toBeTruthy();
      expect(result.payload).toEqual(item.value);
    });

    it(`should pass case ${item.valueType} with external verifier`, async () => {
      const externalVerifier: VerifierFunction = (payload: Uint8Array, signature: Uint8Array) => {
        return verifyData(CoseSignatureAlgorithmEnum.ES256, payload, p256Jwk, signature);
      };

      const result = await verify({
        payload: new Uint8Array(Buffer.from(item.fixture, "hex")),
        verifier: {
          externalVerifier,
        },
      });

      expect(result.verified).toBeTruthy();
      expect(result.payload).toEqual(item.value);
    });
  });

  it("should fail if neither key nor verifier function supplied", async () => {
    await expect(
      verify({
        payload: new Uint8Array(Buffer.from(verificationFixtures[0].fixture, "hex")),
        verifier: {},
      })
    ).rejects.toMatchObject({
      type: CoseErrorTypes.VerifyError,
      message: "Either verifier or key argument must be supplied",
    });
  });

  it("should fail when verifier function supplied failed", async () => {
    await expect(
      verify({
        verifier: {
          externalVerifier: (_: Uint8Array, __: Uint8Array): Promise<boolean> => {
            throw Error("Whoa something un-expected happened");
          },
        },
        payload: new Uint8Array(Buffer.from(verificationFixtures[0].fixture, "hex")),
      })
    ).rejects.toMatchObject({
      type: CoseErrorTypes.ExternalVerifierFunctionError,
      message: "Calling externally supplied verifier function failed",
      details: {
        rawError: new Error("Whoa something un-expected happened"),
      },
    });
  });

  it("should fail if payload in wrong format", async () => {
    await expect(
      verify({
        payload: "payload" as any,
        verifier: {
          publicKey: p256Jwk,
        },
      })
    ).rejects.toThrowError("Expected VerifyOptions");
  });

  it("should fail if payload not CBOR", async () => {
    await expect(
      verify({
        payload: new Uint8Array(Buffer.from("payload")),
        verifier: {
          publicKey: p256Jwk,
        },
      })
    ).rejects.toMatchObject({
      type: CoseErrorTypes.DecodeError,
      message: "Fail to decode payload as CBOR",
    });
  });

  it("should fail if payload has un-expected CBOR tag", async () => {
    await expect(
      verify({
        payload: new Uint8Array(cbor.encode(new Tagged(10, [1, 2, 3, 4]))),
        verifier: {
          publicKey: p256Jwk,
        },
      })
    ).rejects.toMatchObject({
      type: CoseErrorTypes.DecodeError,
      message: "Unexpected CBOR tag, '10'",
    });
  });

  it("should fail if decoded payload is not an array", async () => {
    await expect(
      verify({
        payload: new Uint8Array(cbor.encode({ aMap: true })),
        verifier: {
          publicKey: p256Jwk,
        },
      })
    ).rejects.toMatchObject({
      type: CoseErrorTypes.DecodeError,
      message: "Expecting decoded result to be an array",
    });
  });

  it("should fail if decoded payload is not an array of length 4", async () => {
    await expect(
      verify({
        payload: new Uint8Array(cbor.encode([1])),
        verifier: {
          publicKey: p256Jwk,
        },
      })
    ).rejects.toMatchObject({
      type: CoseErrorTypes.DecodeError,
      message: "Expecting decoded result array length to be 4",
    });
  });
});
