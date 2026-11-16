# Qcord files

Qcord is fixed to **ML-KEM-768**. [qcord.schema.json](qcord.schema.json) describes the shared version-5 attachment; [config.schema.json](config.schema.json) describes the private local version-3 config. Both use JSON Schema 2020-12. These are Qcord JSON formats, not file formats specified by FIPS 203.

- [example.qcord](example.qcord) contains the complete u/v ciphertext and `encrypted_message` with nonce, ciphertext and authentication tag. Its plaintext is `Hello from Qcord.`
- [example.qcord.config.json](example.qcord.config.json) is the sender's config: one local identity and one saved recipient public key with its saved message epoch and shared key K.
- [example.recipient.config.json](example.recipient.config.json) is the matching recipient's config. Both configs can open the example message.

All example private keys, K, m and nonce are fixed, publicly known demonstration values. Never use them for real exchanges. Regenerate with `npm run examples`.

New shared files have these fields:

| Field | Contents |
| --- | --- |
| `qcord_version` | `5` |
| `u` | 3 polynomials × 256 compressed coefficients, each 0–1023 |
| `v` | One polynomial of 256 compressed coefficients, each 0–15 |
| `encrypted_message.nonce_base64` | 12-byte AES-GCM nonce |
| `encrypted_message.ciphertext_base64` | Encrypted message bytes |
| `encrypted_message.authentication_tag_base64` | 16-byte AES-GCM tag |
| `signature_sigma` | Blank ML-DSA placeholders: `{"c_tilde": "", "z": [], "h": []}` |

Pack u using ByteEncode₁₀ and v using ByteEncode₄, least-significant bit first. Concatenate all u bytes followed by v bytes to reconstruct the 1088-byte ML-KEM ciphertext c. The draft shows the uncompressed ring polynomials; only compressed coefficients are sent. v is one polynomial, not a vector of three polynomials.

Generated files keep every polynomial on one row: three `[a, b, …]` rows inside u, then one `[a, b, …]` row for v. The complete example contains all 256 coefficients per row. Whitespace is for readability and does not alter AES-GCM's canonical additional data or the JSON Schema.

The sender derives `(K, r) = SHA3-512(m ∥ SHA3-256(ek))`, where K is the first 32 bytes. H hashes the entire raw 1184-byte ek. The recipient obtains the same K through full ML-KEM.Decaps with their private dk and c. The sender saves K with the attachment filename epoch and reopens the message directly without reproducing the encapsulation.

AES-256-GCM uses K directly to encrypt the UTF-8 message. Every draft edit gets a fresh random nonce. Additional authenticated data is UTF-8 encoding of `JSON.stringify({qcord_version: 5, u: file.u, v: file.v})` with that field order and no whitespace. The authentication tag detects wrong keys or modified data, but does not establish a sender's identity. AES-GCM is outside FIPS 203's ML-KEM scope.

Version-4 configs store `config_version`, `auto_encrypt` (default false), `auto_decrypt` (default true), `save_receipts` (default true), `public_signature`, `private_signature`, `public_encaps`, `private_decaps`, then `recipients` last. Keys are raw Base64: public_encaps is 1184 bytes, private_decaps is 2400 bytes. Each recipient stores `channel_id`, `user_id`, `public_encaps`, and an `encapsulations` list of `{ "message_epoch": 1794690000000, "k": "32 secret bytes in Base64" }`. The epoch is a Unix timestamp in milliseconds matching the `.qcord` filename. Before local key generation, the two identity fields may both be absent. Turning off Save receipts stops saving new keys and preserves existing receipts.

Every new encapsulation samples fresh m, which is never persisted. Existing version-3 receipts are migrated from m to K once; their `message_epoch` is null because the old format did not save it. Epoch filenames use an indexed lookup; legacy or renamed files without an epoch try saved AES keys. Anyone with K can read that message, so keep the config private. Clear config resets the identity and removes all saved recipients and keys. Schema validation checks shape, ranges and lengths; runtime checks additionally verify key coefficients, matching key pairs and AES-GCM authentication.

`signature_sigma` is a separate top-level object below `encrypted_message`. [FIPS 204, Algorithms 26-27](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) encode sigma from the challenge seed c_tilde (not the challenge polynomial c), response vector z, and hint vector h. FIPS 204 does not specify a JSON envelope or signature placement relative to encryption. This is a reserved Qcord representation, not an encoded FIPS 204 signature. No ML-DSA parameter set is selected, keys are not generated, and messages are not signed or verified. The schema permits only the blank components above, and `public_signature` / `private_signature` in the config are empty strings. Older version-5 files may omit `signature_sigma`; new files always include it. The blank placeholder does not change AES-GCM authenticated data.

Reference: [FIPS 203, Algorithms 14, 17, 18, 20, 21 and Tables 2–3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
