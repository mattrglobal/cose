import p256Jwk from "./p-256-jwk";
import p384Jwk from "./p-384-jwk";
import p521Jwk from "./p-521-jwk";
import ed25519Jwk from "./ed25519-jwk";
import rsaJwk from "./rsa-jwk";

import * as headers from "./headers";

// Sign1-tests Positive Test Cases
// @see https://github.com/cose-wg/Examples/tree/master/sign1-tests
import sign1TestPass01 from "./Examples/sign1-tests/sign-pass-01.json";
import sign1TestPass02 from "./Examples/sign1-tests/sign-pass-02.json";
import sign1TestPass03 from "./Examples/sign1-tests/sign-pass-03.json";

export const sign1PositiveTestCases = [sign1TestPass01, sign1TestPass02, sign1TestPass03];

// Sign1-tests Negative Test Cases
// @see https://github.com/cose-wg/Examples/tree/master/sign1-tests
import sign1TestFail01 from "./Examples/sign1-tests/sign-fail-01.json";
import sign1TestFail02 from "./Examples/sign1-tests/sign-fail-02.json";
import sign1TestFail03 from "./Examples/sign1-tests/sign-fail-03.json";
import sign1TestFail04 from "./Examples/sign1-tests/sign-fail-04.json";

export const sign1NegativeTestCases = [sign1TestFail01, sign1TestFail02, sign1TestFail03, sign1TestFail04];

// ECDSA Examples Sign1
// @see https://github.com/cose-wg/Examples/tree/master/ecdsa-examples
import ecdsaExamplesSign1Case1 from "./Examples/ecdsa-examples/ecdsa-sig-01.json";
import ecdsaExamplesSign1Case2 from "./Examples/ecdsa-examples/ecdsa-sig-02.json";
import ecdsaExamplesSign1Case3 from "./Examples/ecdsa-examples/ecdsa-sig-03.json";
import ecdsaExamplesSign1Case4 from "./Examples/ecdsa-examples/ecdsa-sig-04.json";

export const ecdsaExamplesSign1 = [
  ecdsaExamplesSign1Case1,
  ecdsaExamplesSign1Case2,
  ecdsaExamplesSign1Case3,
  ecdsaExamplesSign1Case4,
];

// EDDSA Examples Sign1
// @see https://github.com/cose-wg/Examples/tree/master/eddsa-examples
import eddsaExamplesSign1Case1 from "./Examples/eddsa-examples/eddsa-sig-01.json";

export const eddsaExamplesSign1 = [eddsaExamplesSign1Case1];

// RSA-PSS Examples Sign1
// @see https://github.com/cose-wg/Examples/tree/master/rsa-pss-examples
import rsaPssExampleSign1 from "./Examples/rsa-pss-examples/rsa-pss-01.json";

export const rsaPssExamplesSign1 = [rsaPssExampleSign1];

// Verification Fixtures
import signedArray from "./verification/signed-array-payload.json";
import signedBoolean from "./verification/signed-boolean-payload.json";
import signedNumber from "./verification/signed-number-payload.json";
import signedObject from "./verification/signed-object-payload.json";
import signedString from "./verification/signed-string-payload.json";

// This fixture has a payload that is not of type bstr which is not allowed in COSE
import signedBadPayload from "./verification/signed-bad-payload.json";

export const verificationFixtures = [signedArray, signedBoolean, signedNumber, signedObject, signedString];

export { ed25519Jwk, p256Jwk, p384Jwk, p521Jwk, rsaJwk, signedBadPayload };

export { headers };
