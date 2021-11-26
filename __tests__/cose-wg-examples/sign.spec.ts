import { sign } from "../../src/sign";
import { CoseSignatureAlgorithms } from "../../src/types";

import cbor from "../../src/cbor";
import { base64UrlEncodeNoPadding } from "../../src/codec";
import { decode as hexDecode } from "@stablelib/hex";
import Tagged from "cbor/types/lib/tagged";

import { ecdsaExamplesSign1, eddsaExamplesSign1, sign1PositiveTestCases } from "../__fixtures__";
import { getCurrentNodeMajorVersion } from "../utilities";

/* eslint-disable @typescript-eslint/no-explicit-any */
const runTestCase = async (fixture: any, isDeterministicSignature: boolean): Promise<void> => {
  const protectedHeaders = fixture.input.sign0.protected;
  const unprotectedHeaders = fixture.input.sign0.unprotected;
  const payload = Buffer.from(fixture.input.plaintext);
  const skipTag = fixture.input.failures && fixture.input.failures.RemoveCBORTag ? true : false;

  const key = { ...fixture.input.sign0.key };

  if (key.d_hex) {
    key.d = base64UrlEncodeNoPadding(hexDecode(key.d_hex));
    delete key.d_hex;
  }

  if (key.x_hex) {
    key.x = base64UrlEncodeNoPadding(hexDecode(key.x_hex));
    delete key.x_hex;
  }

  const result = await sign({
    protectedHeaders,
    unprotectedHeaders,
    payload,
    skipEncodingPayload: true,
    algorithm: CoseSignatureAlgorithms[fixture.input.sign0.alg as string] as number,
    privateKey: key,
    skipTag,
  });

  expect(result).toBeInstanceOf(Uint8Array);
  expect(result.length > 0).toBeTruthy();
  let actual;

  // TODO the RemoveCBORTag should trigger no tag being added to the CWS
  if (skipTag) {
    actual = cbor.decodeFirstSync(result);
  } else {
    actual = (cbor.decodeFirstSync(result) as Tagged).value;
  }

  const [protectedHeadersActual, unprotectedHeadersActual, payloadActual, signatureActual] = actual;

  let expected;
  if (skipTag) {
    expected = cbor.decodeFirstSync(fixture.output.cbor);
  } else {
    expected = (cbor.decodeFirstSync(fixture.output.cbor) as Tagged).value;
  }
  const [protectedHeadersExpected, unprotectedHeadersExpected, payloadExpected, signatureExpected] = expected;

  expect(protectedHeadersActual).toEqual(protectedHeadersExpected);
  expect(unprotectedHeadersActual).toEqual(unprotectedHeadersExpected);
  expect(payloadActual).toEqual(payloadExpected);

  expect(signatureActual.length).toEqual(signatureExpected.length);
  if (isDeterministicSignature) {
    expect(signatureActual).toEqual(signatureExpected);
  }
};

describe("cose-wg examples", () => {
  const nodeVersion = getCurrentNodeMajorVersion();

  describe("sign1", () => {
    describe("sign1-tests", () => {
      sign1PositiveTestCases.forEach((fixture) => {
        it(`should pass case ${fixture.title}`, async () => {
          // sign1 tests are all based on ECDSA with p-256
          // which are non-deterministic signatures hence
          // isDeterministicSignature=false
          await runTestCase(fixture, false);
        });
      });
    });
    describe("ecdsa-examples", () => {
      ecdsaExamplesSign1.forEach((fixture) => {
        it(`should pass case ${fixture.title}`, async () => {
          // all ECDSA signatures are non-deterministic signatures
          // hence isDeterministicSignature=false
          await runTestCase(fixture, false);
        });
      });
    });

    if (nodeVersion && nodeVersion >= 14) {
      describe("eddsa-examples", () => {
        eddsaExamplesSign1.forEach((fixture) => {
          it(`should pass case ${fixture.title}`, async () => {
            // EDDSA signatures are deterministic hence
            // isDeterministicSignature=true
            await runTestCase(fixture, true);
          });
        });
      });
    }
  });
});
