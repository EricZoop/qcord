# Qcord

A BetterDiscord Base64 messaging demo. **Base64 is not encryption.**

Copy `qcord.plugin.js` into BetterDiscord's Plugins folder and enable it. A **Qcord ready** toast confirms startup. Click the shield beside the default composer options to open settings:

- **Encode outgoing messages** — converts new chat text before sending.
- **Decoding incoming messages** — displays valid Qcord messages as plain text locally. Turning it off restores the encoded display.
- **PQC key demo** — choose an algorithm and generate session-only keys. The panel reports whether crypto and the key-generation API are available.

Messages use `protocol:version:scheme:payload`, for example:

```text
qcord:v1:b64:SGVsbG8gd29ybGQ=
```

Only this prefix with canonical Base64 and valid UTF-8 is decoded. Invalid messages stay unchanged. Decoded content is displayed as text, not HTML. Outgoing content must fit Discord's 2,000-character limit; errors block sending. Edits, slash commands and attachments are outside this demo.

PQC keys do not encrypt messages yet and are discarded when Qcord stops. ML-KEM establishes shared secrets; ML-DSA and SLH-DSA provide signatures. [BetterDiscord exposes selected Node APIs](https://docs.betterdiscord.app/plugins/introduction/environment), so installing Node separately does not enable PQC inside Discord.

Local tests (the `examples/` folder is Git-ignored; PQC tests require Node 24.8+):

```powershell
node --check qcord.plugin.js
node --test examples/qcordtest.js
```
