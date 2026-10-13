# Qcord

Experimental post-quantum encrypted messaging for BetterDiscord.

Copy `qcord.plugin.js` and place into BetterDiscord's Plugins folder and enable it. 

A **Qcord ready** toast confirms startup. Click the shield beside the default text composer options to open settings:

- **Encrypt outgoing messages** - creates ML-KEM + AES-256-GCM encrypted files for your saved partner key in a one-to-one DM.
- **Decrypt incoming messages** - displays files addressed to your saved private key, with Discord Markdown formatting.
- **My encryption key** - load your saved ML-KEM-512 key and copy your public key as plain Base64, without BEGIN/END wrappers.
- **DM partners** - manage multiple contacts in a scrollable list with avatars, @usernames and user IDs. Open each contact's DM to add their public key; select any saved contact to copy, replace or remove their key. Each one-to-one DM has one partner key.
- **Keys, IDs and message integrity** - learn about public/private keys, post-quantum cryptography, authenticated encryption, and SHA-256 fingerprints. An optional local check verifies your ML-KEM-512 key pair.
- **Future algorithms** - a collapsed roadmap separates future encryption options from digital signatures.

Open the panel for the first time to generate and save your ML-KEM-512 public/private key pair. Later openings reuse those keys. Settings, key pairs, and recipient public keys are stored through BetterDiscord in its Plugins folder's `qcord.config.json`. Keys use Base64-encoded DER without text wrappers. Private keys are stored unencrypted: keep this file private and backed up. Local config files and examples are excluded from Git; the development checks in `scripts/test.cjs` contain no saved private keys.

To set up a conversation:

1. Both parties copy their ML-KEM-512 public key from the panel.
2. Exchange public keys in Discord DMs: public keys are safe to share. Compare the displayed SHA-256 fingerprints over an independent route, such as a call or in person, to verify ownership. A compromised account could substitute a different key; this is an identity check, not a requirement to keep public keys secret. Never share a private key or the config file.
3. Open your one-to-one DM. Paste their complete public key, then click **Save partner**. Paste the complete key text copied by Qcord. Qcord reads the account and conversation IDs from Discord; no @username or manual ID entry is required. Repeat in another contact's DM to add another partner. Your own key is included automatically so you can read sent files. Selecting a contact in settings edits their saved key; sending always uses the partner in the actual DM.
4. Enable outgoing encryption. Enter stages every nonempty message as `YYYY-MM-DD_hh-mm-ss.qcord`, using local time. Review it and press Send or Enter again with the composer empty. Missing recipient keys, unsupported crypto APIs, and encryption/staging errors preserve the draft and block sending.

A **user ID** identifies an account independently of its changeable @username. A **channel ID** identifies the conversation, including a DM. IDs are routing and local key-association data, not proof of key ownership. The encrypted envelope binds its channel ID and public-key fingerprints as authenticated data; its recipient IDs are key fingerprints, not Discord user IDs. Compare fingerprints with your partner.

Each person keeps one local key pair and collects a public key for each contact: N contacts means N contact keys to manage. There is no group key agreement or TreeKEM. New encrypted sending rejects server channels, group DMs, multiple partner keys, and keys saved for a different user ID.

Only Discord-hosted `.qcord` files with a valid envelope are processed, up to 1 MiB including all encryption and Base64 overhead. Invalid or unreadable files keep their attachment card. Links and code blocks are rendered locally, but decoded links do not generate server-side previews.

New encrypted files are ordinary JSON with tab indentation, new lines and `qcord_version: 2`. Both parties need this updated plugin to read new packets. Existing `qcord:v1:pqc:` attachments remain readable. Existing config fields migrate automatically to descriptive snake_case names, preserving key material and contact bindings.

ML-KEM-512 follows the algorithm standardized in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final); Qcord is not a FIPS-validated cryptographic module. ML-KEM establishes a secret; AES encrypts the text:

1. **ML-KEM** produces a **32-byte shared secret** and a **768-byte KEM ciphertext** for each recipient. The matching private key recovers the secret. The secret stays local.
2. **HKDF-SHA256** derives a **32-byte AES wrapping key** from that secret. It stays local too.
3. **AES-256-GCM** encrypts the message with a fresh random **32-byte message key**. Each recipient gets a separately encrypted copy of that message key, protected by their wrapping key. Each AES operation has a public **12-byte nonce** and a **16-byte authentication tag**.
4. **SHA-256** hashes the public key's DER/SPKI encoding into a **32-byte fingerprint**, displayed as 64 hexadecimal characters. A fingerprint identifies key bytes; it does not sign a message.

**There is no 32-byte signature in Qcord.** GCM tags detect changes to protected ciphertext and metadata, but do not establish the sender's identity: anyone with the public keys can construct a fresh valid packet. The file's version, algorithms, channel and ordered recipient fingerprints are authenticated data. Copying a file to a different channel, or modifying protected fields, fails verification. Whitespace and JSON property order may change without breaking decryption. This experimental, unaudited format has no sender identity signatures or forward secrecy.

The packet's fields describe the encrypted bytes; `_base64` means binary data encoded as text, not another encryption layer:

| Field | Meaning |
| --- | --- |
| `qcord_version` | Packet schema version, currently `2` |
| `kem_algorithm`, `encryption_algorithm`, `key_derivation_algorithm` | `ml-kem-512`, `aes-256-gcm`, `hkdf-sha256` |
| `channel_id` | Discord DM channel; visible but authenticated |
| `recipient_key_fingerprints_sha256` | Ordered public-key fingerprints; these are not Discord user IDs |
| `recipients[].public_key_fingerprint_sha256` | Identifies which private key can open this recipient's envelope |
| `recipients[].kem_ciphertext_base64` | ML-KEM ciphertext used to recover that recipient's shared secret |
| `recipients[].wrapped_message_key` | AES-GCM encrypted copy of the message key |
| `encrypted_message` | AES-GCM encrypted message text |
| `nonce_base64` | Public 12-byte nonce within each AES-GCM object |
| `ciphertext_base64` | Encrypted message bytes or encrypted message-key bytes, depending on the containing object |
| `authentication_tag_base64` | 16-byte GCM tag within each AES-GCM object |

The packet contains neither plaintext nor private keys, shared secrets or unwrapped AES keys. Public routing metadata remains visible to Discord.

The local `qcord.config.json` uses these fields (BetterDiscord controls its JSON formatting):

| Field | Meaning |
| --- | --- |
| `config_version` | Local config schema version, currently `2` |
| `encrypt_outgoing_messages`, `decrypt_incoming_messages` | Boolean switches |
| `key_pairs["ml-kem-512"].public_key_spki_base64` | Public key in a DER/SPKI container, encoded as Base64 |
| `key_pairs["ml-kem-512"].private_key_pkcs8_base64` | **Secret, unencrypted** private key in a DER/PKCS#8 container, encoded as Base64 |
| `key_pairs["ml-kem-512"].created_at` | Key creation time in ISO 8601 format |
| `dm_partners[].channel_id`, `dm_partners[].user_id` | Discord conversation and account IDs |
| `dm_partners[].key_algorithm`, `dm_partners[].public_key_spki_base64` | Contact's algorithm and public key |
| `dm_partners[].saved_at` | Last key save time; migrated contacts may omit it because the old config did not record it |

Raw ML-KEM-512 public and private keys are 800 and 1632 bytes respectively; the DER containers add framing bytes before Base64 encoding. Never share this config file.

The shield opens a large modal sized up to 1120px by targeting the BetterDiscord root containing the panel. The panel uses rounded charcoal buttons, aligned copy icons and matching checkmark controls. The modal scrolls; long partner lists have a bounded scroll area. Textarea scrollbars are hidden while the text stays scrollable and selectable. Key sections stack on narrow screens. Educational details are collapsed with chevrons on the right. Your key creation date appears in parentheses beside its heading. Partner avatars and names come from Discord's cached user profiles; missing or unreadable photos show an initial instead.

The plugin bundles [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) 0.7.1 for ML-KEM-512 only. AES-GCM, HKDF and SHA-256 are also bundled through [noble-ciphers](https://github.com/paulmillr/noble-ciphers) and [noble-hashes](https://github.com/paulmillr/noble-hashes). Secure randomness comes from the browser API. No Node crypto functions are required. No runtime download or administrator/root access is required. Sending uses the v2 JSON packet; reading supports v2 and the previous v1 envelope with the existing key encoding.

Post-quantum cryptography uses ordinary computers and aims to resist future quantum attacks; it is different from quantum key distribution. [ML-KEM is already standardized](https://csrc.nist.gov/pubs/fips/203/final). Planned additions have no release dates: ML-KEM-768/1024 sending options, evaluation of [HQC (selected by NIST for standardization)](https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection), and ML-DSA/SLH-DSA signatures for sender verification. Signatures authenticate messages rather than encrypt them.

The composer has a translucent navy-to-blue background while encryption is enabled. The shield button lights up while decryption is enabled.

**Check my key pair** works without another person: it checks ML-KEM key agreement, encrypts/decrypts a local test message, and verifies that a modified authentication tag is rejected. It does not test Discord delivery.

The red **Clear qcord.config.json** button asks for confirmation, then empties the file and BetterDiscord cache, disables encryption/decryption, and clears local key and plaintext caches. No new keys are generated until you click **Create key pair** or reopen the panel. Deleted private keys cannot decrypt previous messages unless restored from backup. The button does not remove already staged Discord attachments.

To develop or rebuild, use Node 20.19+ and run:

```sh
npm ci --ignore-scripts
npm test
npm run build
```

Edit `src/`, then rebuild. [esbuild](https://esbuild.github.io/api/#bundle) combines the source and pinned dependencies into the standalone `qcord.plugin.js`. Copy only that generated file into BetterDiscord's Plugins folder; `node_modules` is needed only for building. Project npm settings and dependency URLs use the public npm registry. The generated file includes dependency licenses, also recorded in `THIRD_PARTY_NOTICES.md`.

| Source | Responsibility |
| --- | --- |
| `src/plugin.js` | Discord lifecycle, composer hooks and attachment rendering |
| `src/messaging.js` | Saved keys, recipients and encrypted file format |
| `src/config.js` | Descriptive config fields and migration preserving existing keys |
| `src/pqc.js` | Bundled PQC operations and key import/export |
| `src/der.js` | DER framing and key text decoding |
| `src/settings.js` | Settings panel |
| `src/styles.css`, `src/button.svg` | Appearance |
| `src/constants.js`, `src/metadata.json` | Shared values and plugin metadata |
| `scripts/build.mjs` | Build and third-party notices |
