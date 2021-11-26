# CBOR Object Signing and Encryption

This repository is home to an incomplete implementation of [RFC 8152](https://tools.ietf.org/html/rfc8152) written in
[Typescript](https://www.typescriptlang.org/).

# Signing

The following algorithms are supported for [COSE_Sign1](https://tools.ietf.org/html/rfc8152#section-2)

| Signing Algorithm                                                | Description                                                                     |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| [ES256](https://tools.ietf.org/html/rfc8152#section-8.1)         | Elliptic Curve Digital Signature Algorithm using the P-256 curve with SHA-256   |
| [ES384](https://tools.ietf.org/html/rfc8152#section-8.1)         | Elliptic Curve Digital Signature Algorithm using the P-384 curve with SHA-384   |
| [ES512](https://tools.ietf.org/html/rfc8152#section-8.1)         | Elliptic Curve Digital Signature Algorithm using the P-512 curve with SHA-512   |
| [EdDSA](https://tools.ietf.org/html/rfc8152#section-8.2)\*       | Elliptic Curve Digital Signature Algorithm using the Ed25519 curve with SHA-512 |
| [PS256](https://datatracker.ietf.org/doc/html/rfc8230#section-2) | RSA Probabilistic Signature Scheme (RSASSA-PSS) with SHA-256                    |
| [PS384](https://datatracker.ietf.org/doc/html/rfc8230#section-2) | RSA Probabilistic Signature Scheme (RSASSA-PSS) with SHA-384                    |
| [PS512](https://datatracker.ietf.org/doc/html/rfc8230#section-2) | RSA Probabilistic Signature Scheme (RSASSA-PSS) with SHA-512                    |

\*Only available in Node environments version 14 and above

## Licensing

See [here](https://learn.mattr.global/docs/terms/sdk-licence-verifier-single-format-cwt-cose) for licence information
