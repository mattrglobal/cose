import { decode as hexDecode } from "@stablelib/hex";
import { CoseErrorTypes, CoseHeaderParameterEnum, decode } from "../src";
import { getHeader, getKid } from "../src/utilities";
import { headers, signedBadPayload, verificationFixtures } from "./__fixtures__";

describe("utilities", () => {
  describe("decode", () => {
    verificationFixtures.forEach((item) => {
      it(`should decode case ${item.valueType}`, async () => {
        const result = await decode(new Uint8Array(Buffer.from(item.fixture, "hex")));
        expect(result.payload).toEqual(item.value);
      });
    });

    it("should fail to decode when bad payload type", async () => {
      await expect(decode(hexDecode(signedBadPayload.fixture))).rejects.toMatchObject({
        type: CoseErrorTypes.DecodeError,
        message: "Expecting payload to be type binary",
      });
    });
  });

  describe("headers", () => {
    it("should give priority to protected header", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.IV_PROTECTED_UNPROTECTED, "hex")));
      const header = getHeader(decoded, CoseHeaderParameterEnum.IV);
      expect(Buffer.from(header as Uint8Array).toString()).toEqual(headers.PROTECTED_HEADER_DATA);
    });

    it("should get unprotected header", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.IV_UNPROTECTED_ONLY, "hex")));
      const header = getHeader(decoded, CoseHeaderParameterEnum.IV);
      expect(Buffer.from(header as Uint8Array).toString()).toEqual(headers.UNPROTECTED_HEADER_DATA);
    });

    it("should get protected header", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.IV_PROTECTED_ONLY, "hex")));
      const header = getHeader(decoded, CoseHeaderParameterEnum.IV);
      expect(Buffer.from(header as Uint8Array).toString()).toEqual(headers.PROTECTED_HEADER_DATA);
    });

    it("should get header passing lookup key as a string", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.IV_PROTECTED_ONLY, "hex")));
      const header = getHeader(decoded, "IV");
      expect(Buffer.from(header as Uint8Array).toString()).toEqual(headers.PROTECTED_HEADER_DATA);
    });

    it("should get header passing lookup key as a number ", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.IV_PROTECTED_ONLY, "hex")));
      const header = getHeader(decoded, 5);
      expect(Buffer.from(header as Uint8Array).toString()).toEqual(headers.PROTECTED_HEADER_DATA);
    });

    it("should get kid and give priority to protected header", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.KID_PROTECTED_UNPROTECTED, "hex")));
      const kid = getKid(decoded);
      expect(Buffer.from(kid).toString()).toEqual(headers.PROTECTED_HEADER_DATA);
    });

    it("should get unprotected kid", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.KID_UNPROTECTED_ONLY, "hex")));
      const kid = getKid(decoded);
      expect(Buffer.from(kid).toString()).toEqual(headers.UNPROTECTED_HEADER_DATA);
    });

    it("should get protected kid", async () => {
      const decoded = await decode(new Uint8Array(Buffer.from(headers.KID_PROTECTED_ONLY, "hex")));
      const kid = getKid(decoded);
      expect(Buffer.from(kid).toString()).toEqual(headers.PROTECTED_HEADER_DATA);
    });
  });
});
