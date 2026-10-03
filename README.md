# Qcord

Base64 encoding and decoding messaging demo

Copy `qcord.plugin.js` into BetterDiscord's Plugins folder and enable it. A **Qcord ready** toast confirms startup. Click the shield beside the default composer options to open settings:

- **Encode outgoing messages** - converts new chat text before sending.
- **Decoding incoming messages** — displays valid Qcord messages as plain text locally. Turning it off restores the encoded display.
- **PQC key demo** — choose an algorithm and generate session-only keys. The panel reports whether Node's crypto and the key-generation API are available.

Messages use `protocol:version:scheme:payload`, for example:

```text
qcord:v1:b64:SGVsbG8gd29ybGQ=
```

