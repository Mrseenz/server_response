# Signing Artifacts

Extracted from repository capture files (`4 handshake/*` and `2 deviceActivation/*`).

## Handshake Signature + Key
- `X-Apple-Sig-Key` length: **65 bytes**
- `X-Apple-Sig-Key` SHA-256: `0999df27bfac77fd137c0f6207507037d244d56b41aafdd09545876815ada32a`
- `X-Apple-Signature` length: **72 bytes**
- `X-Apple-Signature` SHA-256: `6bfe26d8c3f3909ccb3e036fdb532cd86f9eb9fb5aefc0b398b60735901669a7`
- `IngestBody` SHA-256: `97670952bab383102a0a58d2525de7bbadfdd761bfde31583cdd755819a2523b`

## Activation Record Account Token Signature
- `AccountTokenSignature` length: **128 bytes**
- `AccountTokenSignature` SHA-256: `66349eb47f70e0921d69aa66c7b6c8217d56663b0916580ce6749f7c66d950b2`

## Certificate Signatures and Public Keys

### AccountTokenCertificate
- Subject: `subject=C = US, O = Apple Inc., OU = Apple iPhone, CN = Apple iPhone Activation`
- Issuer: `issuer=C = US, O = Apple Inc., OU = Apple Certification Authority, CN = Apple iPhone Certification Authority`
- Signature Algorithm: `sha1WithRSAEncryption`
- Public Key Algorithm: `rsaEncryption`
- Public Key Size: `1024 bit`
- Certificate Signature SHA-256: `4c132745d18f4eb6359034adb75d5c7e559377aba2363cc16d0d731e0765bb35`
- Public Key SHA-256: `2ead346b8693c0fbc3fb2fed07a48977e4762fb4ff73234dfacb0dea26daf4c5`
- PEM file: `artifacts/signing/AccountTokenCertificate.pem`

```pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFAXzRImArmoiHfbS2oPcqAfbE
v0d1jk7GbnX7+4YUlyIfprzBVdlmz2JHYv1+04IzJtL7cL97UI7fk0i0OMY0al8a
+JPQa4Ug611TbqEt+njAmAkge3HXWDBdAXD9MhkC7T/9o77zOQ1oli4cUdzlnYWf
zmW0PduOxuveAeYY4wIDAQAB
-----END PUBLIC KEY-----
```

### DeviceCertificate
- Subject: `subject=CN = 64A13B46-EC96-437E-8148-7D51E7FE31AB, C = US, ST = CA, L = Cupertino, O = Apple Inc., OU = iPhone`
- Issuer: `issuer=C = US, O = Apple Inc., OU = Apple iPhone, CN = Apple iPhone Device CA`
- Signature Algorithm: `sha1WithRSAEncryption`
- Public Key Algorithm: `rsaEncryption`
- Public Key Size: `1024 bit`
- Certificate Signature SHA-256: `e4254d156d0fb6a12193339fbaffa82e0889baabe188cb7532ebae3915a0faf6`
- Public Key SHA-256: `3c366675c41206c8e5333888d78df400880b99c774bda57cd0079f56bc8b1d1a`
- PEM file: `artifacts/signing/DeviceCertificate.pem`

```pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCBTtZm1oomxz/gHxEjQyvRgzEl
pg5mdFcS6q/umJPeJsWne3LvcsUOUZEhghLeWeXgWIwP2UlSDJElwCAU3R8S/Prw
uaIapoJMLa5sudPulTzjTXgQZi5ISeczChr9+2uZVRBHV5fMcXgEwTUYiz9QyHG8
yCjJArBfRonu+nCodQIDAQAB
-----END PUBLIC KEY-----
```

### UniqueDeviceCertificate
- Subject: `subject=ST = California, O = Apple Inc., CN = FDRDC-UCRT-SUBCA`
- Issuer: `issuer=CN = SEP Root CA, O = Apple Inc., ST = California`
- Signature Algorithm: `ecdsa-with-SHA256`
- Public Key Algorithm: `id-ecPublicKey`
- Public Key Size: `256 bit`
- Certificate Signature SHA-256: `ee31198e8dba0fbcb09c9e65d2331ddf06b9da2af7e72090ab798331b37e290e`
- Public Key SHA-256: `5dad52f7b222f142a3e74feccffffa86f28748c11361f061c4016a477e14de03`
- PEM file: `artifacts/signing/UniqueDeviceCertificate.pem`

```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaDc2O/MruYvPVPaUbKR7RRzn66B1
4/8KoUMsEDb7nHkGEMX6eC+0gStGHe4HYMrLyWcap1tDFYmEDykGQ3uM2Q==
-----END PUBLIC KEY-----
```

