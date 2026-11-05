# Qcord · learning edition

A BetterDiscord plugin for composing encrypted `.qcord` attachments and exploring ML-KEM. Install the single generated **qcord.plugin.js** file. It bundles its cryptography and needs no runtime downloads.

## Start a conversation

1. Copy `qcord.plugin.js` into BetterDiscord's Plugins folder and enable Qcord.
2. Open a one-to-one DM and click the Qcord shield. Choose an **ML-KEM parameter set**. Its **NIST security level** appears beside the selector.
3. Open **Contacts & keys → My public key** and share your encapsulation key. Your contact does the same for the same parameter set.
4. In the **Contacts** tab, choose **Add open DM**, paste the contact's public key, and save it. Compare the displayed fingerprint over a separate trusted route, such as a call. Choose **Use this recipient**.
5. Turn on **Quantum conversations** for automatic outgoing encryption and incoming decryption. Type in Discord and press Enter to stage a file; review it and press Send again.

With automatic mode off, ordinary Discord sending works normally and incoming attachments stay as files. Manual composition works with the switch either on or off. Existing unencrypted attachments are not encrypted by Qcord.

## The composer

The composer opens in a native dialog up to **1480 × 920 CSS pixels**, bounded by the window. The parameter selector, NIST level, selected contact, and contact manager occupy a fixed toolbar. Five clickable tabs and Back/Next navigation replace the long expanding form. Equations use 24px type on desktop; polynomial graphics use lime green.

The two-column desktop layout keeps the current lesson and its visualization together. Nested tabs switch the visible explanation or graph. Small windows permit scrolling within the lesson so content remains accessible; long file previews and contact lists have their own scroll areas.

| Stage | Views and actions | Lecture 6 slides |
| --- | --- | --- |
| Write | Enter text, choose a recipient, or make a file automatically | 32–35, 56, 97 |
| Encode | UTF-8 bytes and least-significant-first bits, polynomial mapping, BOM explanation | 10, 57–59, 65–68, 86, 97 |
| Keys | Public matrix, public vector, optional local secret vectors, key format | 34, 56, 64, 72–75, 82, 96 |
| Encapsulate | Encoded random m, noise, u, v, and an editable compression exercise | 53–60, 84–90, 97 |
| Attach | Recovered text, decapsulation visualization, and the exact file | 35, 91–93, 97–98 |

Back/Next preserve the current preview. Editing text, changing recipient, replacing a key, or changing parameter sets invalidates it. **Sample fresh randomness** creates new encapsulation values. The final button stages the exact reviewed file, without re-encrypting it. Open the selected DM and clear any plaintext from the Discord composer before attaching; the walkthrough retains its own message copy.

The separate **Contacts & keys** dialog includes searchable contact cards with avatars, usernames, and badges for saved parameter sets. It has tabs for contacts, your public key, and private-key backup/restoration. Removing a contact key removes only the selected parameter set's binding.

## Parameter sets

The UI calls these NIST security levels; FIPS 203 calls them security categories. Levels are not literal key lengths or claimed bits of security.

| Parameter set | NIST security level | k | η₁ / η₂ | dᵤ / dᵥ | Public ek | Private dk | KEM ciphertext c |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ML-KEM-512 | 1 | 2 | 3 / 2 | 10 / 4 | 800 B | 1632 B | 768 B |
| ML-KEM-768 | 3 | 3 | 2 / 2 | 10 / 4 | 1184 B | 2400 B | 1088 B |
| ML-KEM-1024 | 5 | 4 | 2 / 2 | 11 / 5 | 1568 B | 3168 B | 1568 B |

All sets use `n = 256`, `q = 3329`, and a 32-byte shared secret K. Sizes above are raw bytes; copied keys add DER framing and Base64 encoding. These parameters follow [FIPS 203, Tables 2 and 3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

Changing the set preserves every existing identity and contact key. A missing local key pair is generated once for the chosen set. The selection controls automatic sending; incoming files select their own parameter set from authenticated metadata. Both participants need a compatible saved public/private key for that set. The default remains ML-KEM-768.

## UTF-8 and the BOM

A leading **U+FEFF Byte Order Mark** encodes as **EF BB BF** in UTF-8. Qcord marks those bytes in the preview and preserves the character when decrypting. The decoder explicitly avoids the default behavior that removes a leading BOM; removal previously caused the local text-equality check to fail after successful decryption. See the [WHATWG Encoding Standard](https://encoding.spec.whatwg.org/#dom-textdecoderoptions-ignorebom).

Plugin source and generated `.qcord` JSON use UTF-8 **without an added BOM**. The file parser accepts an optional BOM on the JSON wrapper without stripping one from the encrypted message. Unpaired Unicode surrogates are rejected with an explicit message rather than silently changing text during encoding.

## How the lesson maps to ML-KEM

The course reference is the local `corpus/PQC_Lecture_6_ML-KEM_v3.pdf`. Panels name the relevant slide numbers. **The corpus is local-only and excluded from Git**; it is not needed to run the plugin. Lecture references are labels, not bundled copies of the slides.

**Typed text is not ML-KEM's random m.** The text-to-polynomial display is a mapping exercise. Actual encapsulation draws uniformly random 32-byte m, derives `(K, r) = G(m ∥ H(ek))`, and uses K-PKE to encode and encrypt m. The full chat text is encrypted separately with AES-256-GCM. Exercise values never supply cryptographic randomness.

The lecture uses older pseudocode numbering and some pre-final details. The panel states the differences: final FIPS 203 expands `(ρ, σ) = G(d ∥ byte(k))` and samples `Â[i,j] = SampleNTT(ρ ∥ byte(j) ∥ byte(i))`. The lecture's vector **r⃗** is distinct from the scalar 32-byte seed **r**. A hat denotes an NTT representation; `∘` denotes polynomial multiplication in that representation. Final-standard bytes drive the implementation.

`src/learning.js` reconstructs the mathematics for display. Actual key generation, encapsulation, and decapsulation use the bundled library's public API. A trace is displayed only if its independently reconstructed ciphertext matches the library byte for byte. Private vectors shown in the lesson are local; never share their screenshots. Closing the panel clears reachable numeric buffers, though JavaScript cannot guarantee erasure of strings or garbage-collector copies.

[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) defines key encapsulation. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) define ML-DSA and SLH-DSA signatures. Signatures, certificates, and PKI are deferred lessons.

## File and key behavior

Each version-3 file contains a fresh AES-256-GCM encrypted message and one ML-KEM envelope per distinct participant key. Qcord derives wrapping keys with HKDF-SHA256 and the context `Qcord v3 key wrap`, then wraps a fresh 32-byte AES message key. AES-GCM uses fresh 12-byte nonces and 16-byte tags. HKDF and AES-GCM are Qcord's application layer, outside the lecture's ML-KEM algorithm walkthrough.

The version, algorithms, channel ID, and ordered key fingerprints form authenticated data. A file is bound to its original DM. The sender is included so their saved dk can open their sent files. The file contains no plaintext, private dk, random m, K, or unwrapped AES keys. Public metadata and traffic timing remain visible. Incoming parsing is limited to 1 MiB and supported Discord CDN attachment URLs; BetterDiscord's fetch API buffers downloads before the size check.

**This is an experimental, unaudited learning tool, not a FIPS-validated module.** AES-GCM detects modification but does not authenticate the sender. There are no sender signatures, forward secrecy, replay protection, group key agreement, or certificate management.

Keys and contacts persist under `learning_*` fields in BetterDiscord's `qcord.config.json`. Existing learning-edition ML-KEM-768 keys and version-3 files remain usable. Older version-1/version-2 protocols and their contact bindings are not loaded. Older private-key data on disk is left intact.

Your **dk is stored unencrypted**. Use **Contacts & keys → Private key** for a private backup or restoration. Restoration asks for confirmation and replaces only the selected set's identity; back up that dk first. A lost private key cannot be recovered from its public key.

## Development

Use Node 22.16+ (declared minimum: 20.19). Build source modules into the standalone plugin:

```sh
npm ci --ignore-scripts
npm run build
npm test
```

Browser checks use a local fixture with disposable keys, not a Discord account:

```sh
npx playwright install chromium
npm run test:ui
```

Alternatively set `QCORD_BROWSER` to an installed Chromium/Chrome/Edge executable. Screenshots go to ignored `.tools/ui/`. Crypto tests cover all three sets, BOM preservation, independent ring multiplication, trace equality, two-party decryption, tampering, wrong keys, cancellation, and key retention. Browser checks cover the real native dialogs, aligned controls, avatars, searchable contacts, tab navigation, all parameter sets, exact-file staging, the send hook against mocked Discord actions, desktop overflow, and narrow windows.

These tests do not verify live BetterDiscord integration. Discord's private APIs can change. Qcord reports failure and does not activate if it cannot install its send hook. Once active, attachment-staging failures block submission and preserve the draft.

| Source | Responsibility |
| --- | --- |
| `src/plugin.js` | Discord lifecycle, dialogs, send interception, staging, local rendering |
| `src/messaging.js`, `src/pqc.js`, `src/der.js` | Keys, cryptography, strict imports and packet format |
| `src/parameters.js`, `src/learning.js` | Parameter definitions and verified educational traces |
| `src/settings.js`, `src/contacts.js`, `src/ui.js`, `src/styles.css` | Composer, contact dialog, visual components and layout |
| `scripts/build.mjs`, `scripts/test.cjs`, `scripts/test-ui.mjs` | Build and checks |
