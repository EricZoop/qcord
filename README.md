# Qcord

Experimental post-quantum encrypted messaging for BetterDiscord.

Copy `qcord.plugin.js` and place into BetterDiscord's Plugins folder and enable it. 

A **Qcord ready** toast confirms startup. Click the shield beside the default text composer options to open settings:

- **Encrypt outgoing messages** - creates ML-KEM + AES-256-GCM encrypted files for your saved partner key in a one-to-one DM.
- **Decrypt incoming messages** - displays files addressed to your saved private key, with Discord Markdown formatting.
- **My encryption key** - load your saved ML-KEM-512 key and copy your public key as plain Base64, without BEGIN/END wrappers.
- **DM partner** - paste one public key. Qcord reads the partner user ID and DM channel ID automatically, and binds the saved key to both.
- **Keys, IDs and message integrity** - learn about public/private keys, post-quantum cryptography, authenticated encryption, and SHA-256 fingerprints. An optional local check verifies your ML-KEM-512 key pair.
- **Future algorithms** - a collapsed roadmap separates future encryption options from digital signatures.

Open the panel for the first time to generate and save your ML-KEM-512 public/private key pair. Later openings reuse those keys. Settings, key pairs, and recipient public keys are stored through BetterDiscord in its Plugins folder's `qcord.config.json`. Keys use Base64-encoded DER without text wrappers. Private keys are stored unencrypted: keep this file private and backed up. Config files, tests, and examples are excluded from Git.

To set up a conversation:

1. Both parties copy their ML-KEM-512 public key from the panel.
2. Exchange public keys through a trusted route, and compare the displayed SHA-256 fingerprints. Never share a private key or the config file.
3. Open your one-to-one DM. Use **Paste key** or paste their complete public key, then click **Save key**. Paste the complete key text copied by Qcord. Qcord reads the account and conversation IDs from Discord; no @username or manual ID entry is required. Each DM has one partner key. Your own key is included automatically so you can read sent files.
4. Enable outgoing encryption. Enter stages every nonempty message as `YYYY-MM-DD_hh-mm-ss.qcord`, using local time. Review it and press Send or Enter again with the composer empty. Missing recipient keys, unsupported crypto APIs, and encryption/staging errors preserve the draft and block sending.

A **user ID** identifies an account independently of its changeable @username. A **channel ID** identifies the conversation, including a DM. IDs are routing and local key-association data, not proof of key ownership. The encrypted envelope binds its channel ID and public-key fingerprints as authenticated data; its recipient IDs are key fingerprints, not Discord user IDs. Compare fingerprints with your partner.

Each person keeps one local key pair and collects a public key for each contact: N contacts means N contact keys to manage. There is no group key agreement or TreeKEM. New encrypted sending rejects server channels, group DMs, multiple partner keys, and keys saved for a different user ID.

Only Discord-hosted `.qcord` files with a valid envelope are processed, up to 1 MiB including all encryption and Base64 overhead. Invalid or unreadable files keep their attachment card. Links and code blocks are rendered locally, but decoded links do not generate server-side previews.

Encrypted files use `qcord:v1:pqc:` followed by JSON. A fresh random AES-256-GCM key encrypts the message. Each recipient gets a separate ML-KEM encapsulation and an AES-GCM wrapped copy of that message key, derived through HKDF-SHA256. The channel, scheme, and recipient IDs are bound as authenticated data; files copied into another channel will not decrypt there. Authentication tags are always checked before displaying plaintext: changes to protected ciphertext or metadata fail verification. SHA-256 fingerprints identify public keys; a standalone message hash would not prevent an attacker from replacing both content and its hash. This is an experimental, unaudited format with no sender identity signatures or forward secrecy.

The shield opens a large modal sized up to 1120px by targeting the BetterDiscord root containing the panel. The flat panel retains checkmark controls, uses one scroll region, and hides textarea scrollbars while keeping the text scrollable and selectable. Key sections stack on narrow screens. Educational details are collapsed with chevrons.

The plugin bundles [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) 0.7.1 for ML-KEM-512 only. AES-GCM, HKDF and SHA-256 are also bundled through [noble-ciphers](https://github.com/paulmillr/noble-ciphers) and [noble-hashes](https://github.com/paulmillr/noble-hashes). Secure randomness comes from the browser API. No Node crypto functions are required. No runtime download or administrator/root access is required. Only the current v1 envelope and current key encoding are supported.

Post-quantum cryptography uses ordinary computers and aims to resist future quantum attacks; it is different from quantum key distribution. [ML-KEM is already standardized](https://csrc.nist.gov/pubs/fips/203/final). Planned additions have no release dates: ML-KEM-768/1024 sending options, evaluation of [HQC (selected by NIST for standardization)](https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection), and ML-DSA/SLH-DSA signatures for sender verification. Signatures authenticate messages rather than encrypt them.

The composer has a translucent navy-to-blue background while encryption is enabled. The shield button lights up while decryption is enabled.

**Check my key pair** works without another person: it checks ML-KEM key agreement, encrypts/decrypts a local test message, and verifies that a modified authentication tag is rejected. It does not test Discord delivery.

The red **Clear qcord.config.json** button asks for confirmation, then empties the file and BetterDiscord cache, disables encryption/decryption, and clears local key and plaintext caches. No new keys are generated until you click **Create key pair** or reopen the panel. Deleted private keys cannot decrypt previous messages unless restored from backup. The button does not remove already staged Discord attachments.

To develop or rebuild, use Node 20.19+ and run:

```sh
npm ci --ignore-scripts
npm run build
```

Edit `src/`, then rebuild. [esbuild](https://esbuild.github.io/api/#bundle) combines the source and pinned dependencies into the standalone `qcord.plugin.js`. Copy only that generated file into BetterDiscord's Plugins folder; `node_modules` is needed only for building. Project npm settings and dependency URLs use the public npm registry. The generated file includes dependency licenses, also recorded in `THIRD_PARTY_NOTICES.md`.

| Source | Responsibility |
| --- | --- |
| `src/plugin.js` | Discord lifecycle, composer hooks and attachment rendering |
| `src/messaging.js` | Saved keys, recipients and encrypted file format |
| `src/pqc.js` | Bundled PQC operations and key import/export |
| `src/der.js` | DER framing and key text decoding |
| `src/settings.js` | Settings panel |
| `src/styles.css`, `src/button.svg` | Appearance |
| `src/constants.js`, `src/metadata.json` | Shared values and plugin metadata |
| `scripts/build.mjs` | Build and third-party notices |
