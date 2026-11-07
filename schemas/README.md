# Qcord files

Qcord is fixed to **ML-KEM-768**. [qcord.schema.json](qcord.schema.json) describes the shared version-5 attachment; [config.schema.json](config.schema.json) describes the private local version-3 config. Both use JSON Schema 2020-12. These are Qcord JSON formats, not file formats specified by FIPS 203.

- [example.qcord](example.qcord) contains the complete u/v ciphertext and `encrypted_message` with nonce, ciphertext and authentication tag. Its plaintext is `Hello from Qcord.`
- [example.qcord.config.json](example.qcord.config.json) is the sender's config: one local identity and one saved recipient public key with its original secret m.
- [example.recipient.config.json](example.recipient.config.json) is the matching recipient's config. Both configs can open the example message.

All example private keys, m and nonce are fixed, publicly known demonstration values. Never use them for real exchanges. Regenerate with `npm run examples`.

The shared file has only these fields:

| Field | Contents |
| --- | --- |
| `qcord_version` | `5` |
| `u` | 3 polynomials × 256 compressed coefficients, each 0–1023 |
| `v` | One polynomial of 256 compressed coefficients, each 0–15 |
| `encrypted_message.nonce_base64` | 12-byte AES-GCM nonce |
| `encrypted_message.ciphertext_base64` | Encrypted message bytes |
| `encrypted_message.authentication_tag_base64` | 16-byte AES-GCM tag |

Pack u using ByteEncode₁₀ and v using ByteEncode₄, least-significant bit first. Concatenate all u bytes followed by v bytes to reconstruct the 1088-byte ML-KEM ciphertext c. The draft shows the uncompressed ring polynomials; only compressed coefficients are sent. v is one polynomial, not a vector of three polynomials.

Generated files keep every polynomial on one row: three `[a, b, …]` rows inside u, then one `[a, b, …]` row for v. The complete example contains all 256 coefficients per row. Whitespace is for readability and does not alter AES-GCM's canonical additional data or the JSON Schema.

The sender derives `(K, r) = SHA3-512(m ∥ SHA3-256(ek))`, where K is the first 32 bytes. H hashes the entire raw 1184-byte ek. The recipient obtains the same K through full ML-KEM.Decaps with their private dk and c. The sender can reproduce the original encapsulation from saved m and recipient ek, so the file needs no second copy for the sender.

AES-256-GCM uses K directly to encrypt the UTF-8 message. Every draft edit gets a fresh random nonce. Additional authenticated data is UTF-8 encoding of `JSON.stringify({qcord_version: 5, u: file.u, v: file.v})` with that field order and no whitespace. The authentication tag detects wrong keys or modified data, but does not establish a sender's identity. AES-GCM is outside FIPS 203's ML-KEM scope.

The config contains `config_version`, `public_encaps`, `private_decaps`, `recipients`, and optional booleans `auto_encrypt` (default false) and `auto_decrypt` (default true). Keys are raw Base64: public_encaps is 1184 bytes, private_decaps is 2400 bytes. Each recipient stores `channel_id`, `user_id`, `public_encaps`, and an `encapsulations` list of `{ "m": "32 secret bytes in Base64" }`. Before local key generation, the two identity fields may both be absent.

Every new encapsulation samples fresh m. Retaining original m is a course convenience outside FIPS 203's ephemeral-data lifecycle. Anyone with m and the public ek can recover that exchange's K and text, so keep the config private. Clear config resets the identity and removes all saved recipients and m values. Schema validation checks shape, ranges and lengths; runtime checks additionally verify key coefficients, matching key pairs and AES-GCM authentication.

Reference: [FIPS 203, Algorithms 14, 17, 18, 20, 21 and Tables 2–3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
