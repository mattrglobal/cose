import { decode as hexDecode } from "@stablelib/hex";
import { encodeCoseKey, decodeCoseKey, JwkEcCurve, JsonWebKeyPublic, JwkKty } from "../src";

describe("coseKey", () => {
  const rfc8152Fixtures = [
    {
      name: "RFC8152 Appendix C.7.1 Fixture 1",
      key: {
        kid: "meriadoc.brandybuck@buckland.example",
        kty: JwkKty.EC,
        crv: JwkEcCurve.P256,
        x: "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        y: "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
      } as JsonWebKeyPublic,
      encodedKeyResult: hexDecode(
        "a502d84058246d65726961646f632e6272616e64796275636b406275636b6c616e642e6578616d706c650102200121d840582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d22d84058201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"
      ),
    },
    {
      name: "RFC8152 Appendix C.7.1 Fixture 2",
      key: {
        kid: "11",
        kty: JwkKty.EC,
        crv: JwkEcCurve.P256,
        x: "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        y: "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
      } as JsonWebKeyPublic,
      encodedKeyResult: hexDecode(
        "a502d8404231310102200121d8405820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff22d840582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
      ),
    },
    {
      name: "RFC8152 Appendix C.7.1 Fixture 3",
      key: {
        kid: "bilbo.baggins@hobbiton.example",
        kty: JwkKty.EC,
        crv: JwkEcCurve.P521,
        x: "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
        y: "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
      } as JsonWebKeyPublic,
      encodedKeyResult: hexDecode(
        "a502d840581e62696c626f2e62616767696e7340686f626269746f6e2e6578616d706c650102200321d84058420072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad22d840584201dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475"
      ),
    },
    {
      name: "RFC8152 Appendix C.7.1 Fixture 4",
      key: {
        kid: "peregrin.took@tuckborough.example",
        kty: JwkKty.EC,
        crv: JwkEcCurve.P256,
        x: "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
        y: "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs",
      } as JsonWebKeyPublic,
      encodedKeyResult: hexDecode(
        "a502d8405821706572656772696e2e746f6f6b407475636b626f726f7567682e6578616d706c650102200121d840582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022d8405820f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf822bb"
      ),
    },
  ];

  describe("encode", () => {
    rfc8152Fixtures.forEach((item) => {
      it(`should encode ${item.name}`, async () => {
        const encodedKey = encodeCoseKey(item.key);
        expect(encodedKey).toEqual(item.encodedKeyResult);
      });
    });
  });

  describe("decode", () => {
    rfc8152Fixtures.forEach((item) => {
      it(`should decode ${item.name}`, async () => {
        const decodedKey = decodeCoseKey(item.encodedKeyResult);
        expect(decodedKey).toEqual(item.key);
      });
    });
  });
});
