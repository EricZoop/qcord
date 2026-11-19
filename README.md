# Qcord

A BetterDiscord course tool using **ML-KEM-512, ML-KEM-768, and ML-KEM-1024** (768 by default). Inspect the recipient's public key, derive K, construct `u, v`, then encrypt a message with K. Install the generated **qcord.plugin.js** in BetterDiscord's Plugins folder.

**Your keys** cycles through the three security levels. The public encapsulation/signature keys are side by side, with their private keys beneath in matching columns. Each has its own Copy control; private keys have independent Reveal controls. Explanatory hints stay above the fields. The selected recipient opens the contact editor, where both public keys can be saved.

New attachments are signed with **ML-DSA-44 / 65 / 87**, matching the selected ML-KEM level. **Auto verify** checks decrypted messages against the saved contact's signature key (or your own key for sent messages). Discord's message author determines whose key is used; a file never supplies a trusted verification key. Missing keys and unsigned legacy files remain explicitly unverified.

The existing top-right Qcord message control opens **Check Signature Challenge**. It becomes a check for a verified signature or an error shield with a red bubble for a failed one. With automatic verification off, the control changes when you reach the final challenge check. Download .qcord is available inside the walkthrough.

The walkthrough uses the supplied **PQC Lecture 8**, slides 10, 17 and 25: `Az - ct = w - cs2` and `H(M || HighBits(Az - ct)) = c`. It then expands the simplified equation into full ML-DSA: `c = SampleInBall(c_tilde)`, `w' = Az - c*t1*2^d`, `w1' = UseHint(h, w')`, and `c_tilde' = H(mu || w1Encode(w1'))`. It shows the actual reconstructed high-bit polynomials, received/recomputed challenges, response norm, and hint weight. The reconstruction must agree with the bundled noble ML-DSA verifier before display.


The walkthrough starts with the recipient's key:

1. **Recipient key**: save `public_encaps` and inspect `t̂` and `Â`. The 1184-byte key contains 1152 bytes of encoded `t̂` plus the 32-byte seed `ρ`. `t̂` has 3 polynomials; `Â` has 3 × 3. Each polynomial has 256 coefficients modulo 3329.
2. **Derive K**: sample fresh 32-byte `m`, then compute `(K, r) = SHA3-512(m ∥ SHA3-256(ek))`. The first 32 output bytes are K; the last 32 are the encryption seed r.
3. **Construct u, v**: follow the same seed r from the preceding step through PRF₂ and SamplePolyCBD₂. Nonces 0, 1, 2 generate y; 3, 4, 5 generate e₁; 6 generates e₂. Then ŷ = NTT(y) feeds the u/v equations and worked coefficients. Both u and the single polynomial v have overview plots and detailed coefficient inspectors. The independent polynomial trace must reproduce the library's 1088-byte ciphertext exactly.
4. **Message & attach**: enter the message, encrypt it with AES-256-GCM using K, and review the exact JSON attachment. Attaching saves K locally when Save receipts is enabled. Press Send in Discord to share the file.

Open **Your keys** to share your encapsulation key. All key fields use the same layout. The actual private-key textbox is blurred until revealed; its Copy button is hidden with space reserved so revealing it does not move anything. The selected recipient in the toolbar opens a panel with fields for the recipient’s encapsulation and optional signature public keys. All three levels are accepted. Keys are raw Base64; ML-KEM DER keys remain importable. Supplied key, contact, reset, copy, and upload icons inherit the theme's text color and are bundled with their attribution.

Graphs change their selected coefficient only after a click or during a drag, or through the slider and numbered coefficient buttons. Hovering does not scrub. Static plots and derived values are cached between tab changes. Panels are fully opaque and do not apply background blur; opening a popup hides the underlying walkthrough and its backdrop so surfaces do not stack.

The UI bundles [Inter](https://github.com/rsms/inter) for offline use and keeps the equation typeface. Toolbar controls share a 44 px height, with a quiet Exit button. Button icons use only the supplied SVGs. Vertical scrollbars are hidden while scrolling remains available; the attachment preview keeps a slim horizontal scrollbar. Graph dragging updates once per animation frame, and reduced-motion preferences disable the preview transitions.

The toolbar places the recipient first (filling the remaining width), followed by Your keys, Auto encrypt, Auto decrypt, Auto verify, Save receipts, and Exit. It has four independent switches:

- **Auto encrypt** (off by default): typing in Discord and pressing Enter prepares a `.qcord` attachment and clears the plaintext draft only after successful staging. Review it, then press Send again. A subdued blue gradient and a thin border mark the Discord composer while this is on. Missing keys, failures, or cancellation keep the draft and do not send plaintext. This encrypts text; existing non-Qcord attachments are not encrypted.
- **Auto decrypt** (on by default): automatically opens visible `.qcord` attachments using saved sender K receipts or your private key. The composer button shows a white logo on a blue background while this is on. Switching it off restores original attachments and clears rendered plaintext, including pending decryptions. Manual file opening still works with either automatic switch off.
- **Auto verify** (off by default): verifies signed messages using saved public signature keys, independently of encryption and decryption.
- **Save receipts** (on by default): saves each outgoing attachment's epoch and K so you can reopen prior messages. Switch it off to stop saving new keys; existing receipts stay available.

The switches persist separately. **Previous step** navigates the walkthrough. In a subpanel, **Go Back**, Escape, or an outside click returns to the main popup. Clicking outside again exits Qcord, as does **Exit** on the main popup. **Open .qcord file** in the footer decrypts a `.qcord` file already downloaded to your device; its tooltip explains that action.

The polynomial equations use column vectors:

```text
u = Aᵀy + e₁
v = tᵀy + μ + e₂
μ = Decompress₁(ByteDecode₁(m))
```

FIPS 203 calls the ephemeral vector y; a course may call it r⃗. It is distinct from the 32-byte seed r. In row notation the first equation is `uᵀ = yᵀA + e₁ᵀ`, matching the course's `rA + e₁`. Products occur in `ℤ₃₃₂₉[X]/(X²⁵⁶ + 1)`; implementation and displayed traces use the NTT arithmetic of Algorithm 14.

The version-6 `.qcord` file groups its ciphertext polynomials in `kem` (key encapsulation mechanism):

```json
{
  "qcord_version": 6,
  "kem": {
    "u": ["2, 3, or 4 arrays of 256 compressed coefficients"],
    "v": ["256 compressed coefficients"]
  },
  "encrypted_message": {
    "nonce_base64": "12 fresh random bytes in Base64",
    "ciphertext_base64": "encrypted UTF-8 message in Base64",
    "authentication_tag_base64": "16-byte GCM tag in Base64"
  },
  "signature_sigma": {"c_tilde": "Base64 challenge seed", "z": ["response polynomials"], "h": ["nonzero hint positions per polynomial"]}
}
```

The signature fields contain a canonical ML-DSA signature: `c_tilde` is a Base64 challenge seed, `z` stores signed response coefficients, and `h` stores sorted nonzero hint positions per polynomial. These reconstruct the standard encoded signature. ML-DSA signs `Qcord signed envelope v1\n` followed by canonical JSON for `{qcord_version, kem: {u, v}, encrypted_message: {nonce_base64, ciphertext_base64, authentication_tag_base64}}`, using pure ML-DSA with empty context. This binds the ciphertext, nonce, authentication tag, KEM components and version. Whitespace changes do not affect verification. Old blank/missing signatures remain readable and are labeled unsigned.

The saved signature public key must be exchanged through a trusted channel. A successful check establishes a match to that saved key; an unknown sender or missing key is not marked as verified. A modified signature produces a red warning bubble when the AES-GCM layer still decrypts; AES-GCM failures keep the original attachment visible.

This abbreviated illustration uses placeholders. See [schemas/README.md](schemas/README.md) for the schemas and complete, valid [example attachment](schemas/example.qcord), [sender config](schemas/example.qcord.config.json), and [recipient config](schemas/example.recipient.config.json).

The file stores compressed u (3 × 256 coefficients, 10 bits each) and v (one polynomial, 4 bits per coefficient). Each u polynomial occupies one bracketed row, and v occupies one bracketed row. The preview scrolls horizontally for long rows. This formatting changes no coefficients or authentication data. FIPS 203 ByteEncode reconstructs the packed ML-KEM ciphertext exactly. AES-GCM encrypts the full text directly with K, using a fresh 12-byte nonce and a 16-byte tag. The version and u/v are authenticated as canonical JSON additional data. There are no wrapping keys, sender ciphertext copies, or recipient key hashes.

With **Auto decrypt** on, `.qcord` attachments in visible one-to-one DMs are detected and decrypted automatically for both parties:

- The sender selects the saved K by the attachment filename's epoch and decrypts directly with AES-GCM.
- The recipient calls ML-KEM.Decaps with their private dk and the packed u/v ciphertext. Internally it recovers m′, derives K, and performs re-encryption and implicit rejection.
- Both use K with the file's nonce, ciphertext and tag. Wrong keys or modified files fail AES-GCM authentication. The separate ML-DSA signature authenticates against the locally saved sender key.

Successfully decrypted attachments display as white text with Discord Markdown, including bold, lists, links and code blocks. A subtle box sits directly below the username when the original message has no caption. Its top-right control opens signature verification; the walkthrough includes the `.qcord` download link. Discord's renderer supplies Markdown support; if it is unavailable or fails, Qcord displays safe plain text. Manual **Open .qcord file** uses the same renderer.

Failed or unsupported files stay visible as their original attachments. Automatic downloads accept HTTPS Discord CDN attachment URLs, and parsing is limited to 1 MiB; BetterDiscord's native fetch buffers downloads before the size check. Repeated scans reuse pending or completed results. Stopping Qcord, resetting config, or replacing keys clears displayed plaintext and restores the original attachments.

The version-5 local config starts with `auto_encrypt`, `auto_decrypt`, `auto_verify`, and `save_receipts`, followed by `config_version`, `key_sets`, and `recipients`. Each of the three security levels in `key_sets` stores `public_encaps`, `private_decaps`, `public_signature`, and `private_signature` in that order. Unused levels have blank strings until first generated. Existing version-4 configs migrate without changing keys or receipts. Version-5 message files remain readable with their original authenticated structure. Each recipient stores their public key once and `{ "message_epoch": 1794690000000, "k": "32-byte shared key in Base64" }` per attached message. The epoch is the Unix timestamp in milliseconds used in the attachment filename. Sender replay looks up that epoch and decrypts directly with K. Turn off **Save receipts** beside Auto encrypt/decrypt to stop retaining keys for new attachments; existing receipts remain. New drafts always sample fresh m; neither m nor plaintext is saved.

**Clear config & reset key**, in **Your keys**, shows a confirmation warning. Confirming deletes saved contacts, saved message keys, and all encryption/signature identities, then generates a new ML-KEM-768 pair and restores the switch defaults. Share the new public key with contacts. Older files need the old private-key/config backup. Installing and enabling this version also cleans stale `learning_*` fields, multi-set `key_pairs`, old toggles, and redundant parameter settings, including configurations already marked version 2.

This is a course tool, not a FIPS-validated module. [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) defines ML-KEM; AES-GCM is the application message layer. Retaining K for course replay differs from the standard's ephemeral-data lifecycle. The config contains unencrypted private material; keep it local. JavaScript cannot guarantee memory erasure. Version-3 encrypted-chat files and version-4 KEM-only files are not loaded. Ordinary Discord sending works normally when auto-encrypt is off. Discord's private send API can change; automatic encryption stays unavailable if Qcord cannot install its send hook.

Each new `.qcord` file still gets a fresh encapsulation and m. This walkthrough does not introduce shared conversation sessions or signature schemes.

For development, use Node 20.19 or later:

```sh
npm ci --ignore-scripts
npm run examples
npm run build
npm test
npm run test:ui
```

Browser checks serve a temporary website on `127.0.0.1`, using disposable keys and mocked Discord APIs. They automatically use installed Edge or Chrome, then an installed Playwright Chromium. No browser download is needed when a supported browser is already installed. Set `QCORD_BROWSER` to override the executable path. This avoids the missing-browser and certificate-chain errors caused by browser downloads behind a corporate proxy. If downloading a browser is necessary, configure Node with your organization's trusted CA certificate using `NODE_EXTRA_CA_CERTS`.

For an interactive website you can inspect yourself:

```sh
npm run preview:ui
```

The bottom-left filename buttons open `qcord.config.json` and the current epoch-named `.qcord` file in a JSON viewer with syntax coloring, scrolling, Refresh, and Close file controls. The message file becomes available when a draft is prepared and updates as the message changes; the config viewer shows the disposable preview settings and keys. These inspection controls are only in the local preview.

Open the printed localhost URL, normally `http://127.0.0.1:4173`. Stop it with Ctrl+C. It uses no Discord account. `QCORD_UI_PORT` selects a different port. Screenshots and tab timing measurements from `npm run test:ui` go to ignored `.tools/ui/`. These are local fixture checks, not live Discord integration or a performance guarantee for Discord's renderer.

The preview includes **Verified message** and **Failed signature** buttons at the bottom right. They create real local signed examples, enable Auto verify for the demonstration, and close the composer so the message is visible. Click its check/error control to inspect the lecture-based walkthrough. No Discord account is involved.

Run `npm run test:signatures:ui` for the signature-specific browser checks, in addition to `npm test` and `npm run test:ui`.
