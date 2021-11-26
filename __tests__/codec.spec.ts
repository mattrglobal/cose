import { base64UrlDecodeNoPadding, base64UrlEncodeNoPadding, bytesToString, stringToBytes } from "../src/codec";

describe("codec", () => {
  describe("bytes <=> string", () => {
    it("converts a string to bytes", () => {
      expect(stringToBytes("123")).toEqual(Uint8Array.from([49, 50, 51]));
    });

    it("converts a byte to string", () => {
      expect(bytesToString(Uint8Array.from([49, 50, 51]))).toEqual("123");
    });

    it.each([[JSON.stringify({ a: 1 })], ["i am good"], ["this should pass"]])("should work with %p", (str) => {
      expect(bytesToString(stringToBytes(str))).toEqual(str);
    });
  });

  describe("base64url with No Padding", () => {
    it("encodes an Uint8Array", () => {
      expect(base64UrlEncodeNoPadding(Uint8Array.from([1, 2, 3, 62, 64]))).toEqual("AQIDPkA");
    });

    it("decodes an Uint8Array", () => {
      expect(base64UrlDecodeNoPadding("AQIDPkA")).toEqual(Uint8Array.from([1, 2, 3, 62, 64]));
    });

    it("throws an error when decoding a string containing excessive padding", () => {
      expect(() => base64UrlDecodeNoPadding("AQIDPkA===")).toThrowError();
    });

    it("throws an error when decoding when the modulo is 1", () => {
      expect(() => base64UrlDecodeNoPadding("AQIDP")).toThrowError();
    });
  });
});
