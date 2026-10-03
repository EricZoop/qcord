# Qcord

Post Quantum Encryption messaging plugin for BetterDiscord

The current implementation is a **Wingdings-style text effect and PQC key-generation demo, not encrypted messaging**.

Copy `qcord.plugin.js` into the folder opened by **Discord Settings → BetterDiscord → Plugins → Open Plugins Folder**, then enable Qcord. A small **Q** button appears immediately to the right of the attachment button. Like `example_translator.js`, it opens a settings modal. The panel contains the text-effect toggle, PQC algorithm selection, key generation, and a read-only public-key field. The effect starts off; its state and selected key algorithm are saved locally. The supplied SVG can replace the placeholder through `BUTTON_SVG` in the plugin.

While the text effect is on, ordinary chat messages submitted with Enter or the send button are converted synchronously before Discord's internal `sendMessage` function receives them. Your draft remains readable while typing. The plugin sends actual Unicode dingbat symbols, rather than applying a Wingdings font to the original text. Every UTF-8 byte becomes two symbols, including punctuation, whitespace, emoji, and non-English text. For example, `Hi` becomes `✄✉✆✍`. Recipients can see the symbols without installing the plugin.

If conversion fails, the message format is unrecognized, or the encoded content exceeds 2,000 symbols, Qcord skips the send function and requests that Discord retain the draft. It does not retry with plaintext. ASCII text therefore supports up to 1,000 input characters; multibyte text supports fewer.

This intercepts **ordinary new chat messages only**. Edits, slash commands, forum-post creation, attachment contents/names, and other Discord submission paths are outside this proof of concept. Disabling the effect or Qcord restores normal plaintext sending. It is not a guarantee that plaintext can never reach Discord through other paths, other plugins, or a future client change. The substitution is trivially reversible and provides no cryptographic protection.

Key generation uses Node's built-in [`crypto.generateKeyPair`](https://nodejs.org/api/crypto.html#cryptogeneratekeypairtype-options-callback), asynchronously, with no extra dependencies. The panel offers ML-KEM-512/768/1024 for key encapsulation, ML-DSA-44/65/87 for lattice-based signatures, and SLH-DSA-SHA2-128f for hash-based signatures. ML-KEM establishes a shared secret; ML-DSA and SLH-DSA sign messages rather than encrypting them. These implement the families standardized by [NIST FIPS 203, 204 and 205](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved).

**Runtime requirement:** native ML-DSA was added in Node 24.6, ML-KEM in 24.7, and SLH-DSA in 24.8. However, [BetterDiscord exposes only selected Node polyfills](https://docs.betterdiscord.app/plugins/introduction/environment), not the complete Node API. `util` is not available, and its crypto polyfill may not expose `generateKeyPair` at all. Qcord therefore uses the callback API directly, disables key generation with an explanatory message if that function is missing, and reports errors if the selected algorithm is unsupported. Installing a newer Node on your PATH does not change Discord's plugin API. For portable JavaScript PQC in a future bundled plugin, [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) implements all three families. No code is downloaded or installed by Qcord at runtime.

Demo keys are held only in plugin memory. The panel displays only the public key in SPKI PEM format. Generating again replaces the previous pair; stopping/reloading Qcord drops its references to the private key. There is no private-key persistence/export, recipient-key exchange, message encryption, or decryption yet. A messaging protocol needs authenticated recipient keys, a KEM-derived encryption key, authenticated encryption such as AES-256-GCM, and a defined wire format before these keys protect messages.

For multiple author credits, use one metadata string, for example `@author EricZoop, AnotherAuthor`. BetterDiscord documents a single `author` field and a single `authorId`; comma-separated names are display credits, not multiple linked identities. Keep the existing ID for the primary author. No additional names have been invented in the plugin header.

The implementation uses BetterDiscord's documented [Webpack lookup](https://docs.betterdiscord.app/api/Webpack), [Patcher](https://docs.betterdiscord.app/api/Patcher), [UI modal](https://docs.betterdiscord.app/api/UI), [DOM styling](https://docs.betterdiscord.app/api/DOM), [Data storage](https://docs.betterdiscord.app/api/Data), and [observer/onSwitch lifecycle](https://docs.betterdiscord.app/plugins/introduction/structure). Discord's send module and composer CSS classes remain internal implementation details and need live verification after client updates. Translator is a reference for the button/panel behavior; Qcord does not require its BDFDB library or copy its translation code.

Run local checks with:

```powershell
node --check qcord.plugin.js
node --test examples/qcordtest.js
```

The local `examples/` directory is ignored by Git. It holds `qcordtest.js` and `example_translator.js` for development; these files are not distributed with the plugin. The test command above requires that local copy. Run it on Node 24.8+ with PQC support. It uses real native key generation and verifies KEM shared-secret agreement and signatures, alongside mocked BetterDiscord send/UI checks.

For a live check in a test channel: open the Q panel, toggle the effect, and send the same message with the effect off and on using both Enter and the send button; confirm only symbols appear when on. Test replies, Unicode, channel navigation, reload persistence, the size-limit error, and plugin disable/re-enable. Generate keys for each family and verify only a public key is shown. Use the Network tab in Discord's developer tools to inspect the outgoing message request's `content` and verify it contains symbols only. The automated checks do not validate a running Discord client.
