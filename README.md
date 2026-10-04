# Qcord

Base64 encoding and decoding messaging demo

Copy `qcord.plugin.js` and place into BetterDiscord's Plugins folder and enable it. 

A **Qcord ready** toast confirms startup. Click the shield beside the default text composer options to open settings:

- **Encode outgoing messages** - converts new chat text before sending.
- **Decoding incoming messages** - displays valid Qcord messages as plain text locally. Turning it off restores the encoded display.
- **PQC key demo** - choose an algorithm and generate session-only keys. The panel reports whether Node's crypto and the key-generation API are available.

While outgoing encoding is enabled, pressing Enter stages every nonempty message as `YYYY-MM-DD_hh-mm-ss.qcord` in the composer, using your local time. Review it and press Send (or Enter again with the composer empty); if staging fails, your draft is kept.

Incoming decoding displays valid Qcord text and `.qcord` attachments as regular text under the sender. Earlier timestamped Qcord `.txt` attachments also remain readable. Only Discord-hosted attachments with a supported filename and a valid envelope are decoded (up to 1 MiB). Invalid files stay visible; turning decoding off restores the file cards. Base64 is not encryption.

Messages use `protocol:version:scheme:payload`, for example:

```text
qcord:v1:b64:SGVsbG8gd29ybGQ=
```

The composer border has a blue gradient fading to transparent at the top while outgoing encoding is enabled. Its normal background stays unchanged. The shield button lights up while incoming decoding is enabled. Decoded messages and attachments use Discord's Markdown renderer for clickable links, code blocks, and text formatting. Link previews are not generated from the decoded text.
