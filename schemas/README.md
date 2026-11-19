# Qcord file formats

Qcord supports ML-KEM-512 / ML-KEM-768 / ML-KEM-1024, paired with ML-DSA-44 / ML-DSA-65 / ML-DSA-87 identities. These are Qcord JSON formats. FIPS 203 and FIPS 204 do not prescribe these envelopes.

[qcord.schema.json](qcord.schema.json) validates new version-6 attachments and legacy version-5 attachments. [config.schema.json](config.schema.json) describes the version-5 local config. Both use JSON Schema 2020-12.

## Message attachment

```json
{
  "qcord_version": 6,
  "kem": {
    "u": ["2, 3, or 4 arrays, each with 256 compressed coefficients"],
    "v": ["256 compressed coefficients"]
  },
  "encrypted_message": {
    "nonce_base64": "12 random bytes in Base64",
    "ciphertext_base64": "encrypted UTF-8 text in Base64",
    "authentication_tag_base64": "16-byte GCM tag in Base64"
  },
  "signature_sigma": {"c_tilde": "Base64 challenge seed", "z": ["signed response polynomials"], "h": ["sorted nonzero hint positions"]}
}
```

`kem` means key encapsulation mechanism. Its `u` vector and `v` polynomial together encode the ML-KEM ciphertext. Two, three, or four u polynomials identify ML-KEM-512, 768, or 1024. The first two use 10-bit u and 4-bit v coefficients; 1024 uses 11 and 5 bits. Pack each polynomial with ByteEncode, least-significant bit first, and concatenate u then v to reconstruct the ciphertext. Files keep each polynomial on one row for inspection.

AES-256-GCM encrypts the UTF-8 message directly with K and a fresh random nonce. Its additional authenticated data is UTF-8 `JSON.stringify({qcord_version: 6, kem: {u: file.kem.u, v: file.kem.v}})` in that order. Version-5 files retain their original `JSON.stringify({qcord_version: 5, u: file.u, v: file.v})` authentication. Moving vectors between versions requires resealing; merely editing the version or JSON envelope fails authentication.

The sender derives `(K, r) = SHA3-512(m || SHA3-256(ek))`, with K in the first 32 bytes. The recipient recovers the same K through ML-KEM.Decaps. Sender receipts store K for direct reopening. Authentication detects wrong keys and modified ciphertext; it does not establish sender identity.

`signature_sigma` stores actual ML-DSA signatures. The challenge seed `c_tilde` is canonical Base64 (32 / 48 / 64 decoded bytes). The response `z` has 4 / 5 / 7 polynomials of 256 signed coefficients. The sparse hint vector `h` has 4 / 6 / 8 lists of strictly increasing coefficient indices, with at most 80 / 55 / 75 nonzero hints in total. Runtime validation reconstructs and validates the standard signature encoding; cryptographic verification also enforces the response norm bound.

Pure ML-DSA with empty context signs a domain-separated canonical payload: `Qcord signed envelope v1\n` followed by JSON for `{qcord_version, kem: {u, v}, encrypted_message: {nonce_base64, ciphertext_base64, authentication_tag_base64}}`, preserving that field order. Signature fields themselves are excluded. This covers all encrypted envelope contents. Each message edit gets a fresh nonce and signature.

Verification uses locally pinned public signature keys and, for Discord attachments, the actual message author. Files do not carry trusted identity keys. The lecture walkthrough reconstructs the full challenge and checks its decision against noble's public ML-DSA.verify API. Blank/missing signatures on older files remain readable as unsigned. Changing or removing a signature never produces a verified status.


## Local config

Boolean settings come first: `auto_encrypt`, `auto_decrypt`, `auto_verify`, `save_receipts`. They are followed by `config_version: 5`, `key_sets`, and `recipients`.

`key_sets` contains `ml-kem-512`, `ml-kem-768`, and `ml-kem-1024`. Each object has exactly four fields in display order:

1. `public_encaps`
2. `private_decaps`
3. `public_signature`
4. `private_signature`

All keys are raw Base64. Unused levels have blank strings and generate keys when first used. Version-4 configs migrate their existing default identity and separate encryption/signature maps into this structure without rotating keys or losing receipts.

Recipients store channel/user IDs, their public encapsulation key, an optional public signature key, and an `encapsulations` list of `{ "message_epoch": 1794690000000, "k": "32-byte shared key in Base64" }`. The epoch matches the attachment filename; older receipts without one use null. Turning off Save receipts stops new receipts and preserves existing ones. Older receipts containing m are migrated to K.

The complete [example attachment](example.qcord), [sender config](example.qcord.config.json), and [recipient config](example.recipient.config.json) use public, deterministic example secrets. Never use them for real exchanges.

Clear config removes all identities and receipts and generates a new default identity. Runtime checks verify key coefficients, matching encryption key pairs, ciphertext bounds, and AES-GCM authentication in addition to the schema checks.
