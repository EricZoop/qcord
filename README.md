# Qcord

A BetterDiscord course tool for **FIPS 203 ML-KEM**. Inspect a recipient's public key, derive a shared key, construct the ciphertext pair `u, v`, and attach one `.qcord` file. Install the generated **qcord.plugin.js** in BetterDiscord's Plugins folder.

The walkthrough has four steps:

1. **Recipient key** — save the recipient's `public_encaps`, detect ML-KEM-512 / 768 / 1024 from raw key length, and inspect the public matrix and vector.
2. **Derive K** — sample fresh 32-byte `m` and show `(K, r) = SHA3-512(m ∥ SHA3-256(ek))`. The first 32 output bytes are `K`; the last 32 are seed `r`.
3. **Construct u, v** — inspect actual polynomial values, noise, coefficient sums, and compression. The trace must reproduce the library ciphertext byte for byte before display.
4. **Attach** — review the exact JSON, save `m` locally for that recipient's original encapsulation, and stage the file in their DM. Press Send in Discord to share it.

Open **Contacts & keys → My public key** to share your own encapsulation key. Paste a recipient's key into Contacts; its length selects the parameter set automatically. Public and private keys use raw Base64. Existing DER keys remain importable. The first step shows exactly the `public_encaps` saved in your config.

| Parameter set | Raw ek | k | t̂ | Â | du / dv | Packed c |
| --- | --- | --- | --- | --- | --- | --- |
| ML-KEM-512 | 800 B | 2 | 2 polynomials | 2 × 2 | 10 / 4 | 768 B |
| ML-KEM-768 | 1184 B | 3 | 3 polynomials | 3 × 3 | 10 / 4 | 1088 B |
| ML-KEM-1024 | 1568 B | 4 | 4 polynomials | 4 × 4 | 11 / 5 | 1568 B |

Every polynomial has 256 coefficients modulo 3329. The key contains `ByteEncode₁₂(t̂) ∥ ρ`, where `ρ` is a 32-byte seed used to reconstruct `Â`. Thus `len(ek) = 384k + 32`. Hats mark NTT representations. The parameter names are not public-key bit lengths; NIST security categories are 1, 3, and 5 respectively.

Using column vectors and coefficient polynomials:

```text
u = Aᵀy + e₁
v = tᵀy + μ + e₂
μ = Decompress₁(ByteDecode₁(m))
```

FIPS 203 calls the ephemeral vector `y`; a course may call it `r⃗`. It is sampled using the 32-byte seed `r`, and is distinct from that seed. With row vectors the first equation is `uᵀ = yᵀA + e₁ᵀ`, matching the course's `rA + e₁`. Products occur in `ℤ₃₃₂₉[X]/(X²⁵⁶ + 1)`; the implementation uses NTT arithmetic as specified in Algorithm 14.

The shared file contains only `qcord_version`, `parameter_set`, compressed `u` arrays and compressed `v` coefficients. `u` is a vector of k polynomials; `v` is one polynomial. Packing these arrays with FIPS 203 ByteEncode reconstructs ciphertext `c` exactly. JSON is a readable Qcord transport format, larger than packed `c`.

See [schemas/README.md](schemas/README.md) for the JSON Schemas, [complete example attachment](schemas/example.qcord), [sender config](schemas/example.qcord.config.json), and [matching recipient config](schemas/example.recipient.config.json). Example secrets are public demonstration data. Regenerate them with `npm run examples`.

The local config saves each recipient public key once and a separate `m` for every attached encapsulation. It stores no extra key hashes, ciphertext copies, or `K`. Saved `m` plus that recipient's public key reproduces the original `K` and ciphertext; every new draft samples fresh randomness. Replacing or removing a contact key removes its saved encapsulations.

Select **Open .qcord locally** to obtain `K`. For a sender's previously attached file, Qcord matches the selected recipient's saved `m` by reproducing its ciphertext. For an incoming file, it uses the saved private key and the library's full ML-KEM.Decaps, including re-encryption and implicit rejection. A modified file or wrong private key also produces a key; decapsulation exposes no success flag. ML-KEM alone does not authenticate a sender.

This version establishes keys only. Discord chat text sends normally. It has no text-encryption lesson, automatic send interception, AES wrapper, or sender ciphertext copy. Version-3 encrypted-chat files are not handled. Existing saved key pairs and contact bindings migrate once to config version 2 and plain field names.

**Course tool, not a FIPS-validated module.** The config stores private keys and `m` unencrypted; keep it local. Retaining `m` for the course deviates from FIPS 203's ephemeral intermediate-data destruction requirements and permits recovery of that encapsulation's `K`. JavaScript cannot guarantee memory erasure. The code uses bundled `@noble/post-quantum`; it does not claim module validation.

Reference: [FIPS 203, Algorithms 14, 17, 18, 20, 21 and Tables 2–3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

For development, use Node 20.19 or later:

```sh
npm ci --ignore-scripts
npm run examples
npm run build
npm test
npm run test:ui
```

Browser checks use disposable keys in a local fixture. Install Playwright Chromium with `npx playwright install chromium`, or set `QCORD_BROWSER` to an installed Chromium/Chrome/Edge executable. Screenshots go to ignored `.tools/ui/`. Live Discord integration is not covered by the fixture.
