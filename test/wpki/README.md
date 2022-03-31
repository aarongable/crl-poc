# Test WebPKI Hierarchy

This directory contains keypairs and certificates for this repository's various components to use when signing objects that would be part of the public Web PKI.

It includes both an RSA-based and an ECDSA-based hierarchy. It does not include keypairs for the root, because this system should never need access to root key material. It does not include end-entity certificates, because test should dynamically generate those when needed.

## Usage

To load an issuing certificate from this directory, include a stanza like the following in a component's configuration:

```json
"issuers": [
   {
      "useForRSALeaves": true,
      "useForECDSALeaves": false,
      "issuerURL": "http://example.com/issuer",
      "ocspURL": "http://example.com/ocsp",
      "crlURL": "http://example.com/crl",
      "location": {
         "file": "test/wpki/key.pem",
         "certFile": "test/wpki/cert.pem",
         "numSessions": 2
      }
   }
]
```
