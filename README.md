# Qcord

A BetterDiscord course tool using **ML-KEM-768 only**. Inspect the recipient's public key, derive K, construct `u, v`, then encrypt a message with K. Install the generated **qcord.plugin.js** in BetterDiscord's Plugins folder.

The walkthrough starts with the recipient's key:

1. **Recipient key**: save `public_encaps` and inspect `t̂` and `Â`. The 1184-byte key contains 1152 bytes of encoded `t̂` plus the 32-byte seed `ρ`. `t̂` has 3 polynomials; `Â` has 3 × 3. Each polynomial has 256 coefficients modulo 3329.
2. **Derive K**: sample fresh 32-byte `m`, then compute `(K, r) = SHA3-512(m ∥ SHA3-256(ek))`. The first 32 output bytes are K; the last 32 are the encryption seed r.
3. **Construct u, v**: inspect actual noise and coefficient calculations. The NTT formulas appear above the worked coefficients. The independent polynomial trace must reproduce the library's 1088-byte ciphertext exactly.
4. **Message & attach**: enter the message, encrypt it with AES-256-GCM using K, and review the exact JSON attachment. Attaching saves m locally. Press Send in Discord to share the file.

Open **Your keys** to share your encapsulation key. Both keys use the same field layout. The actual private-key textbox is blurred until revealed; its Copy button is hidden with space reserved so revealing it does not move anything. The separate **Contacts** button opens a panel with one field to paste, edit and save a contact key; saving does not create another field. Only ML-KEM-768 keys are accepted. Keys are raw Base64, with existing ML-KEM-768 DER keys still importable. Supplied key, contact, reset, copy, and upload icons inherit the theme's text color and are bundled with their attribution.

Graphs change their selected coefficient only after a click or during a drag, or through the slider and numbered coefficient buttons. Hovering does not scrub. Static plots and derived values are cached between tab changes. Panels are fully opaque and do not apply background blur; opening a popup hides the underlying walkthrough and its backdrop so surfaces do not stack.

The UI bundles [Inter](https://github.com/rsms/inter) for offline use and keeps the equation typeface. Toolbar controls share a 44 px height, with a bordered Exit button. Button icons use only the supplied SVGs. Vertical scrollbars are hidden while scrolling remains available; the attachment preview keeps a slim horizontal scrollbar. Graph dragging updates once per animation frame, and reduced-motion preferences disable the preview transitions.

The toolbar has two independent switches:

- **Auto encrypt** (off by default): typing in Discord and pressing Enter prepares a `.qcord` attachment and clears the plaintext draft only after successful staging. Review it, then press Send again. A restrained green gradient and border glow mark the Discord composer while this is on. Missing keys, failures, or cancellation keep the draft and do not send plaintext. This encrypts text; existing non-Qcord attachments are not encrypted.
- **Auto decrypt** (on by default): automatically opens visible `.qcord` attachments using saved sender m values or your private key. The shield is lit while this is on. Switching it off restores original attachments and clears rendered plaintext, including pending decryptions. Manual file opening still works with either switch off.

The switches persist separately. **Previous step** navigates the walkthrough. In a subpanel, **Go Back**, Escape, or an outside click returns to the main popup. Clicking outside again exits Qcord, as does **X** on the main popup. **Open file** in the footer decrypts a `.qcord` file already downloaded to your device; its tooltip explains that action.

The polynomial equations use column vectors:

```text
u = Aᵀy + e₁
v = tᵀy + μ + e₂
μ = Decompress₁(ByteDecode₁(m))
```

FIPS 203 calls the ephemeral vector y; a course may call it r⃗. It is distinct from the 32-byte seed r. In row notation the first equation is `uᵀ = yᵀA + e₁ᵀ`, matching the course's `rA + e₁`. Products occur in `ℤ₃₃₂₉[X]/(X²⁵⁶ + 1)`; implementation and displayed traces use the NTT arithmetic of Algorithm 14.

The version-5 `.qcord` file has four fields:

```json
{
  "qcord_version": 5,
  "u": ["three arrays of 256 compressed coefficients"],
  "v": ["256 compressed coefficients"],
  "encrypted_message": {
    "nonce_base64": "12 fresh random bytes in Base64",
    "ciphertext_base64": "encrypted UTF-8 message in Base64",
    "authentication_tag_base64": "16-byte GCM tag in Base64"
  }
}
```

This abbreviated illustration uses placeholders. See [schemas/README.md](schemas/README.md) for the schemas and complete, valid [example attachment](schemas/example.qcord), [sender config](schemas/example.qcord.config.json), and [recipient config](schemas/example.recipient.config.json).

The file stores compressed u (3 × 256 coefficients, 10 bits each) and v (one polynomial, 4 bits per coefficient). Each u polynomial occupies one bracketed row, and v occupies one bracketed row. The preview scrolls horizontally for long rows. This formatting changes no coefficients or authentication data. FIPS 203 ByteEncode reconstructs the packed ML-KEM ciphertext exactly. AES-GCM encrypts the full text directly with K, using a fresh 12-byte nonce and a 16-byte tag. The version and u/v are authenticated as canonical JSON additional data. There are no wrapping keys, sender ciphertext copies, or recipient key hashes.

With **Auto decrypt** on, `.qcord` attachments in visible one-to-one DMs are detected and decrypted automatically for both parties:

- The sender reproduces K from the selected recipient's saved public key and the original saved m, matching its u/v to the file.
- The recipient calls ML-KEM.Decaps with their private dk and the packed u/v ciphertext. Internally it recovers m′, derives K, and performs re-encryption and implicit rejection.
- Both use K with the file's nonce, ciphertext and tag. Wrong keys or modified files fail AES-GCM authentication. This does not authenticate the sender's identity.

Successfully decrypted attachments display as white text with Discord Markdown, including bold, lists, links and code blocks. A subtle box sits directly below the username when the original message has no caption. Its Qcord logo is a download link for the `.qcord` file. Discord's renderer supplies Markdown support; if it is unavailable or fails, Qcord displays safe plain text. Manual **Open file** uses the same renderer.

Failed or unsupported files stay visible as their original attachments. Automatic downloads accept HTTPS Discord CDN attachment URLs, and parsing is limited to 1 MiB; BetterDiscord's native fetch buffers downloads before the size check. Repeated scans reuse pending or completed results. Stopping Qcord, resetting config, or replacing keys clears displayed plaintext and restores the original attachments.

The local config contains `config_version`, `public_encaps`, `private_decaps`, `recipients`, and the two boolean preferences `auto_encrypt` / `auto_decrypt`. Missing preferences default to false / true respectively. Each recipient stores their public key once and `{ "m": "…" }` per attached encapsulation. New drafts always sample fresh m. The config stores neither K nor plaintext.

**Clear config & reset key**, in **Your keys**, shows a confirmation warning. Confirming deletes saved contacts, saved m values, and the current key pair, then generates a new ML-KEM-768 pair and restores the automatic-mode defaults. Share the new public key with contacts. Older files need the old private-key/config backup. Installing and enabling this version also cleans stale `learning_*` fields, multi-set `key_pairs`, old toggles, and redundant parameter settings, including configurations already marked version 2.

This is a course tool, not a FIPS-validated module. [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) defines ML-KEM; AES-GCM is the application message layer. Retaining m for course replay differs from the standard's ephemeral-data lifecycle. The config contains unencrypted private material; keep it local. JavaScript cannot guarantee memory erasure. Version-3 encrypted-chat files and version-4 KEM-only files are not loaded. Ordinary Discord sending works normally when auto-encrypt is off. Discord's private send API can change; automatic encryption stays unavailable if Qcord cannot install its send hook.

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

Open the printed localhost URL, normally `http://127.0.0.1:4173`. Stop it with Ctrl+C. It uses no Discord account. `QCORD_UI_PORT` selects a different port. Screenshots and tab timing measurements from `npm run test:ui` go to ignored `.tools/ui/`. These are local fixture checks, not live Discord integration or a performance guarantee for Discord's renderer.
