import { verify } from "../../src/verify";

import { base64UrlEncodeNoPadding } from "../../src/codec";
import { decode as hexDecode } from "@stablelib/hex";

import {
  ecdsaExamplesSign1,
  sign1PositiveTestCases,
  sign1NegativeTestCases,
  eddsaExamplesSign1,
} from "../__fixtures__";
import { getCurrentNodeMajorVersion } from "../utilities";

/* eslint-disable-next-line @typescript-eslint/no-explicit-any */
const decodeJwkKey = (key: any): any => {
  if (key.d_hex) {
    key.d = base64UrlEncodeNoPadding(hexDecode(key.d_hex));
    delete key.d_hex;
  }

  if (key.x_hex) {
    key.x = base64UrlEncodeNoPadding(hexDecode(key.x_hex));
    delete key.x_hex;
  }

  if (key.y_hex) {
    key.y = base64UrlEncodeNoPadding(hexDecode(key.y_hex));
    delete key.y_hex;
  }

  if (key.p_hex) {
    key.p = base64UrlEncodeNoPadding(hexDecode(key.p_hex));
    delete key.p_hex;
  }

  if (key.q_hex) {
    key.q = base64UrlEncodeNoPadding(hexDecode(key.q_hex));
    delete key.q_hex;
  }

  return key;
};

/* eslint-disable @typescript-eslint/no-explicit-any */
const runTestCase = async (fixture: any, expectedResult: boolean): Promise<void> => {
  try {
    let verifier = fixture.input.sign0
      ? { publicKey: fixture.input.sign0.key }
      : fixture.input.sign.signers.map((item: any) => {
          return { publicKey: item.key };
        });

    if (Array.isArray(verifier)) {
      verifier = verifier.map((item: any) => {
        return {
          publicKey: decodeJwkKey(item.publicKey),
        };
      });
    } else {
      verifier = { publicKey: decodeJwkKey(verifier.publicKey) };
    }

    const result = await verify({
      payload: new Uint8Array(Buffer.from(fixture.output.cbor, "hex")),
      verifier,
      additionalAuthenticatedData: fixture.input.sign0.external
        ? Buffer.from(fixture.input.sign0.external, "hex")
        : undefined,
    });
    expect(result.verified).toEqual(expectedResult);
  } catch (err) {
    if (expectedResult) {
      fail(err);
    }
  }
};

describe("cose-wg examples", () => {
  const nodeVersion = getCurrentNodeMajorVersion();

  describe("verify - sign1", () => {
    describe("sign1-tests", () => {
      sign1PositiveTestCases.forEach((fixture) => {
        it(`should pass case ${fixture.title}`, async () => {
          await runTestCase(fixture, true);
        });
      });
      sign1NegativeTestCases.forEach((fixture) => {
        it(`should fail case ${fixture.title}`, async () => {
          await runTestCase(fixture, false);
        });
      });
    });

    describe("ecdsa-examples", () => {
      ecdsaExamplesSign1.forEach((fixture) => {
        it(`should pass case ${fixture.title}`, async () => {
          await runTestCase(fixture, true);
        });
      });
    });

    if (nodeVersion && nodeVersion >= 14) {
      describe("eddsa-examples", () => {
        eddsaExamplesSign1.forEach((fixture) => {
          it(`should pass case ${fixture.title}`, async () => {
            await runTestCase(fixture, true);
          });
        });
      });
    }
  });
});
