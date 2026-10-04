# Qcord

Experimental post-quantum encrypted messaging for BetterDiscord.

Copy `qcord.plugin.js` and place into BetterDiscord's Plugins folder and enable it. 

A **Qcord ready** toast confirms startup. Click the shield beside the default text composer options to open settings:

- **Encrypt outgoing messages** - creates ML-KEM + AES-256-GCM encrypted files for the public keys configured in the current channel.
- **Decrypt incoming messages** - displays files addressed to your saved private key, with Discord Markdown formatting. Also reads older Base64 messages.
- **Native PQC algorithm test** - tests actual key generation and KEM round trips or signature verification in Discord's runtime. A readable dark dropdown distinguishes KEMs from signatures.

Open the panel for the first time to generate and save your default ML-KEM-768 public/private key pair. Later openings reuse those keys. Settings, PEM key pairs for each tested scheme, and recipient public keys are stored through BetterDiscord in its Plugins folder's `qcord.config.json`. Private keys are stored unencrypted: keep this file private and backed up. Config files, tests, and examples are excluded from Git.

To set up a conversation:

1. Both parties choose the same chat encryption scheme and copy their public PEM key from the panel.
2. Exchange public keys through a trusted route, and compare the displayed SHA-256 fingerprints. Never share a private key or the config file.
3. Open the desired Discord channel, paste the recipients' complete public PEM blocks, and click **Save recipient keys**. Up to 15 recipient keys are supported; your own key is included automatically so you can read sent messages. Each participant configures their own recipients.
4. Enable outgoing encryption. Enter stages every nonempty message as `YYYY-MM-DD_hh-mm-ss.qcord`, using local time. Review it and press Send or Enter again with the composer empty. Missing recipient keys, unsupported crypto APIs, and encryption/staging errors preserve the draft and block sending.

Only Discord-hosted `.qcord` files with a valid envelope are processed, up to 1 MiB including all encryption and Base64 overhead. Invalid or unreadable files keep their attachment card. Earlier timestamped Qcord `.txt` files and inline Base64 messages remain readable; those older messages are not encrypted. Links and code blocks are rendered locally, but decoded links do not generate server-side previews.

Encrypted files use `qcord:v2:pqc:` followed by JSON. A fresh random AES-256-GCM key encrypts the message. Each recipient gets a separate ML-KEM encapsulation and an AES-GCM wrapped copy of that message key, derived through HKDF-SHA256. The channel, scheme, and recipient IDs are bound as authenticated data; files copied into another channel will not decrypt there. This is an experimental, unaudited format with no sender identity signatures or forward secrecy. ML-DSA/SLH-DSA tests do not add signatures to chat files.

The panel reports runtime Node/OpenSSL versions, crypto/KEM API availability, per-scheme test results, saved key-generation time, public/private DER key sizes, last message encryption/decryption time, and actual `.qcord` file bytes. Hover over a decrypted message for its time; staging an outgoing file also shows its encryption time and size. Timings are local elapsed milliseconds including async scheduling, not isolated CPU benchmarks. Encryption excludes key generation and upload; decryption excludes download. CPU clock cycles are unavailable through the JavaScript APIs and are not estimated from elapsed time.

The listed ML-KEM, ML-DSA and SLH-DSA families are standardized by NIST. Other candidates or selected algorithms such as HQC and Falcon require implementations outside this native-only plugin. See [NIST's PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography) and [Node's crypto API](https://nodejs.org/api/crypto.html). Discord's embedded runtime must support the chosen APIs; installing a newer standalone Node does not upgrade Discord's crypto runtime. No administrator/root access is required.

The composer has a translucent navy-to-blue background while encryption is enabled. The shield button lights up while decryption is enabled.
