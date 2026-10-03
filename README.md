# Qcord

Base64 encoding and decoding messaging demo

Copy `qcord.plugin.js` into BetterDiscord's Plugins folder and enable it. A **Qcord ready** toast confirms startup. Click the shield beside the default composer options to open settings:

- **Encode outgoing messages** - converts new chat text before sending.
- **Decoding incoming messages** — displays valid Qcord messages as plain text locally. Turning it off restores the encoded display.
- **PQC key demo** — choose an algorithm and generate session-only keys. The panel reports whether Node's crypto and the key-generation API are available.

If encoded text exceeds 2,000 characters, Qcord stages it as `message_YYYY-MM-DD_hh-mm-ss.txt` in the composer, using your local time. The file contains the encoded Qcord envelope. Review it and press Send; staging does not send the message. If staging fails, your draft is kept. Incoming auto-decoding currently applies to inline messages, not attached files.

Messages use `protocol:version:scheme:payload`, for example:

```text
qcord:v1:b64:SGVsbG8gd29ybGQ=
```
