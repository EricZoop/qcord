# Qcord

Base64 encoding and decoding messaging demo

Copy `qcord.plugin.js` into BetterDiscord's Plugins folder and enable it. A **Qcord ready** toast confirms startup. Click the shield beside the default composer options to open settings:

- **Encode outgoing messages** - converts new chat text before sending.
- **Decoding incoming messages** — displays valid Qcord messages as plain text locally. Turning it off restores the encoded display.
- **PQC key demo** — choose an algorithm and generate session-only keys. The panel reports whether Node's crypto and the key-generation API are available.

If encoded text exceeds 2,000 characters, Qcord stages it as `qcord_YYYY-MM-DD_hh-mm-ss.txt` in the composer, using your local time. Review it and press Send; if staging fails, your draft is kept.

Incoming decoding displays valid Qcord text and timestamped Qcord attachments as regular text under the sender. Only Discord-hosted attachments with the matching filename and a valid envelope are decoded (up to 1 MiB). Invalid files stay visible; turning decoding off restores the file cards. Base64 is not encryption.

Messages use `protocol:version:scheme:payload`, for example:

```text
qcord:v1:b64:SGVsbG8gd29ybGQ=
```

Run the attachment regression check with `node --test tests/attachments.test.js`. It uses mocked Discord/DOM APIs; attachment display should also be checked in the Discord client after reloading the plugin.
