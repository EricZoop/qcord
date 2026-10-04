# Qcord

Experimental post-quantum encrypted messaging for BetterDiscord.

Copy `qcord.plugin.js` and place into BetterDiscord's Plugins folder and enable it. 

A **Qcord ready** toast confirms startup. Click the shield beside the default text composer options to open settings:

- **Encrypt outgoing messages** - creates ML-KEM + AES-256-GCM encrypted files for the public keys configured in the current channel.
- **Decrypt incoming messages** - displays files addressed to your saved private key, with Discord Markdown formatting.
- **My encryption key** - load your saved ML-KEM-512 key and copy your public key as plain Base64, without BEGIN/END wrappers.
- **Recipients** - add an @username label and public key, then copy or remove entries. Lists are saved per channel.
- **How your message is protected** - learn about public/private keys, post-quantum cryptography, authenticated encryption, and SHA-256 fingerprints. An optional local check verifies your ML-KEM-512 key pair.
- **Coming next** - a collapsed roadmap separates future encryption options from digital signatures.

Open the panel for the first time to generate and save your ML-KEM-512 public/private key pair. Later openings reuse those keys. Settings, key pairs, and recipient public keys are stored through BetterDiscord in its Plugins folder's `qcord.config.json`. New keys use Base64-encoded DER without PEM wrappers; existing PEM keys remain readable. Private keys are stored unencrypted: keep this file private and backed up. Config files, tests, and examples are excluded from Git.

Upgrading from another scheme: exchange ML-KEM-512 public keys and add recipients for that scheme before sending. Old keys and recipient lists are preserved, and existing ML-KEM-768/1024 files remain decryptable with their saved private keys. New outgoing files always use ML-KEM-512.

To set up a conversation:

1. Both parties copy their ML-KEM-512 public key from the panel.
2. Exchange public keys through a trusted route, and compare the displayed SHA-256 fingerprints. Never share a private key or the config file.
3. Open the desired Discord channel. Enter a recipient's @username, use **Paste public key** or paste their complete public key into the field, and click **Add recipient**. Plain Base64 and existing PEM formats are accepted. Repeat for up to 15 recipients. Usernames are local labels, not verified Discord identities. Your own key is included automatically. Existing saved recipient keys appear as unnamed entries until you replace them with named entries.
4. Enable outgoing encryption. Enter stages every nonempty message as `YYYY-MM-DD_hh-mm-ss.qcord`, using local time. Review it and press Send or Enter again with the composer empty. Missing recipient keys, unsupported crypto APIs, and encryption/staging errors preserve the draft and block sending.

Only Discord-hosted `.qcord` files with a valid envelope are processed, up to 1 MiB including all encryption and Base64 overhead. Invalid or unreadable files keep their attachment card. Legacy Base64 messages and `.txt` attachments are no longer decoded. Links and code blocks are rendered locally, but decoded links do not generate server-side previews.

Encrypted files use `qcord:v2:pqc:` followed by JSON. A fresh random AES-256-GCM key encrypts the message. Each recipient gets a separate ML-KEM encapsulation and an AES-GCM wrapped copy of that message key, derived through HKDF-SHA256. The channel, scheme, and recipient IDs are bound as authenticated data; files copied into another channel will not decrypt there. Authentication tags are always checked before displaying plaintext: changes to protected ciphertext or metadata fail verification. SHA-256 fingerprints identify public keys; a standalone message hash would not prevent an attacker from replacing both content and its hash. This is an experimental, unaudited format with no sender identity signatures or forward secrecy.

The panel expands to 1120px, with spacious checkmark controls and side-by-side key and recipient sections. It stacks into one column in smaller containers. Copy/paste buttons and distinct action colors make key exchange easier.

The plugin bundles [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) 0.7.1 for ML-KEM-512, plus ML-KEM-768/1024 for older incoming files. Signature demos have been removed. AES-GCM, HKDF and SHA-256 are also bundled through [noble-ciphers](https://github.com/paulmillr/noble-ciphers) and [noble-hashes](https://github.com/paulmillr/noble-hashes). Secure randomness comes from the browser API. No Node crypto functions are required. No runtime download or administrator/root access is required. Existing ML-KEM PEM keys, fingerprints and version 2 encrypted files remain compatible.

Post-quantum cryptography uses ordinary computers and aims to resist future quantum attacks; it is different from quantum key distribution. [ML-KEM is already standardized](https://csrc.nist.gov/pubs/fips/203/final). Planned additions have no release dates: ML-KEM-768/1024 sending options, evaluation of [HQC (selected by NIST for standardization)](https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection), and ML-DSA/SLH-DSA signatures for sender verification. Signatures authenticate messages rather than encrypt them.

The composer has a translucent navy-to-blue background while encryption is enabled. The shield button lights up while decryption is enabled.

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
| `src/pem.js` | PEM and DER framing for existing keys |
| `src/settings.js` | Settings panel |
| `src/styles.css`, `src/button.svg` | Appearance |
| `src/constants.js`, `src/metadata.json` | Shared values and plugin metadata |
| `scripts/build.mjs` | Build and third-party notices |
