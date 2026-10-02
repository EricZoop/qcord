# Qcord

Post Quantum Encryption messaging plugin for BetterDiscord

The current implementation is a **Wingdings-style proof of concept, not encryption**.

Copy `qcord.plugin.js` into the folder opened by **Discord Settings → BetterDiscord → Plugins → Open Plugins Folder**, then enable Qcord. A small **WD** switch appears immediately to the right of the attachment button in the message composer. It starts off; clicking it enables the effect globally across channels and saves your choice locally.

While WD is on, ordinary chat messages submitted with Enter or the send button are converted synchronously before Discord's internal `sendMessage` function receives them. Your draft remains readable while typing. The plugin sends actual Unicode dingbat symbols, rather than applying a Wingdings font to the original text. Every UTF-8 byte becomes two symbols, including punctuation, whitespace, emoji, and non-English text. For example, `Hi` becomes `✄✉✆✍`. Recipients can see the symbols without installing the plugin.

If conversion fails, the message format is unrecognized, or the encoded content exceeds 2,000 symbols, Qcord skips the send function and requests that Discord retain the draft. It does not retry with plaintext. ASCII text therefore supports up to 1,000 input characters; multibyte text supports fewer.

This intercepts **ordinary new chat messages only**. Edits, slash commands, forum-post creation, attachment contents/names, and other Discord submission paths are outside this proof of concept. Disabling WD or Qcord restores normal plaintext sending. It is not a guarantee that plaintext can never reach Discord through other paths, other plugins, or a future client change. The substitution is trivially reversible and provides no cryptographic protection.

The implementation uses BetterDiscord's documented [Webpack lookup](https://docs.betterdiscord.app/api/Webpack), [Patcher](https://docs.betterdiscord.app/api/Patcher), [DOM styling](https://docs.betterdiscord.app/api/DOM), [Data storage](https://docs.betterdiscord.app/api/Data), and [observer/onSwitch lifecycle](https://docs.betterdiscord.app/plugins/introduction/structure). Discord's send module and composer CSS classes remain internal implementation details and need live verification after client updates. There is no external plugin library dependency.

Run local checks with:

```powershell
node --check qcord.plugin.js
node --test tests/qcord.test.js
```

For a live check in a test channel: send the same message with WD off and on using both Enter and the send button; confirm only symbols appear with WD on. Test replies, Unicode, channel navigation, reload persistence, the size-limit error, and plugin disable/re-enable. Use the Network tab in Discord's developer tools to inspect the outgoing message request's `content` and verify it contains symbols only. The automated checks use mocked BetterDiscord APIs; they do not validate a running Discord client.
