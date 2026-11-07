# Qcord files

`qcord.schema.json` describes the shared `.qcord` attachment. `config.schema.json` describes local `qcord.config.json` state. Both use JSON Schema 2020-12. The JSON wrapper is a Qcord format, not a format specified by FIPS 203.

- [example.qcord](example.qcord): a complete ML-KEM-768 encapsulation with compressed `u` (3 × 256 coefficients, 10 bits) and `v` (256 coefficients, 4 bits).
- [example.qcord.config.json](example.qcord.config.json): the sender's config. It saves the recipient's `public_encaps` once and one secret `m` per original encapsulation. Local identity keys are separate from recipient keys.
- [example.recipient.config.json](example.recipient.config.json): the matching recipient's config, for decapsulation of the example.

All example keys and `m` are fixed, publicly known demonstration values. Regenerate with `npm run examples`; never use them for real exchanges.

Public keys are raw Base64: decode `public_encaps` to get `ByteEncode₁₂(t̂) ∥ ρ`. The parameter set follows from raw length (800 / 1184 / 1568 bytes). All polynomials have 256 coefficients modulo 3329; `t̂` has 2 / 3 / 4 polynomials and `Â` has 2×2 / 3×3 / 4×4. Expand `Â` from the final 32-byte seed `ρ`.

During drafting, Qcord shows uncompressed `u` and `v`. The file stores `Compress_du(u)` and `Compress_dv(v)` as integer arrays so the structure remains visible. Pack each polynomial least-significant bit first with `ByteEncode_du` / `ByteEncode_dv` and concatenate all `u` bytes followed by `v` bytes to reconstruct standard ciphertext `c`. `v` is one polynomial, not a k-element vector. JSON numbers require more bytes than packed ciphertext.

The local config stores neither `K` nor redundant key hashes or ciphertext copies. The sender reproduces an original encapsulation with its saved `m` and recipient `ek`:

```text
(K, r) = SHA3-512(m ∥ SHA3-256(ek))
K = first 32 bytes; r = last 32 bytes
```

Each new exchange samples fresh `m`. Keeping `m` is a course convenience and deviates from FIPS 203's ephemeral intermediate-data destruction requirements. Anyone with `m` and public `ek` can recover that exchange's `K`. Treat the entire config as private. Changing or removing a recipient key removes its saved encapsulations.

The receiver uses their private `dk` and `c` with ML-KEM.Decaps. Modified ciphertexts and unrelated private keys produce a key too, through implicit rejection; this flow does not expose a validity flag or authenticate the sender. JSON Schema validates structure and lengths; the runtime additionally checks public-key coefficients, canonical Base64, and matching key pairs.

Reference: [FIPS 203, Algorithms 14, 17, 18 and Tables 2–3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
