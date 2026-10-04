/**
 * @name Qcord
 * @author Eric, Arsh, Yasser
 * @authorId 215269534540496896
 * @version 0.0.1
 * @description Experimental ML-KEM + AES-256-GCM encrypted chat files, saved local keys, and PQC timing tests. Reads older Base64 messages too.
 * @invite GSdMfMBW5g
 * @source https://github.com/EricZoop/qcord
 */

"use strict";

const NAME = "Qcord";
let Crypto;
try { Crypto = require("crypto"); }
catch { Crypto = null; } // Encoding still works if the optional key API is unavailable.
const SCHEMES = ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f"];
const KEM_SCHEMES = SCHEMES.filter(scheme => scheme.startsWith("ml-kem"));
// Use one cache name for settings and keys: Windows filenames ignore case.
const KEY_STORE = "qcord";
const ENCRYPTED_PREFIX = "qcord:v2:pqc:";
const BUTTON_SVG =
`
<svg xmlns="http://www.w3.org/2000/svg"
     viewBox="2 0 98 87"
     preserveAspectRatio="xMidYMid meet">
    <path d="m15.617 41.047c-4.4844 2.9961-7.9922 6.2266-10.262 9.4727-2.4922 3.5664-3.4531 7.1211-2.4922 10.34 1.5938 5.3516 8.1562 9.1289 17.465 10.895 1.6055 0.30469 3.2852 0.54688 5.0586 0.73047 5.2578 0.53906 11.09 0.50391 17.242-0.14453-2.4609-1.3672-4.7148-3.0977-6.5703-5.1445-3.1367-3.4648-5.1484-7.8203-5.1484-12.875v-16.355c0.007813-0.89062 0.55469-1.7266 1.4414-2.0469 2.8828-1.0508 5.7656-2.2617 8.5703-3.6211 2.707-1.3086 5.3555-2.7656 7.8867-4.3398 0.6875-0.44531 1.5977-0.48047 2.3359-0.019531 2.543 1.5859 5.207 3.0508 7.9258 4.3633 2.7539 1.332 5.582 2.5273 8.4102 3.5625 0.92188 0.25781 1.5977 1.1016 1.5977 2.1055v18.602c-0.003906 0.19531-0.03125 0.39063-0.085937 0.58984l-0.60156 2.1211c-0.96484 3.4141-2.8516 6.3672-5.293 8.8008 6.2422-1.9531 11.902-4.3711 16.773-7.0859l0.14453-0.082032c3.6016-2.0195 6.7461-4.1953 9.3555-6.4531 5.9961-5.1953 9.0391-10.723 7.8789-15.562l-0.12891-0.46484c-0.87109-2.9102-3.2461-5.3711-6.7422-7.293-1.75-0.96094-3.7695-1.7852-6.0156-2.4609v21.949c0 1.207-0.97656 2.1836-2.1836 2.1836-1.207 0-2.1836-0.98047-2.1836-2.1836v-22.402c-1.7109-0.39844-3.4375-0.87109-5.1641-1.4141-0.09375-0.023438-0.18359-0.050781-0.27344-0.085938-3.7578-1.1914-7.5-2.6953-11.051-4.4336-5.0586-2.4766-9.7383-5.4414-13.52-8.6719-3.7812 3.2305-8.4609 6.1953-13.52 8.6719-5.2695 2.582-10.965 4.6445-16.488 5.9297v26.098c0 1.4258 0.097656 2.8086 0.28906 4.1719 0.19922 1.3945 0.48828 2.7266 0.86328 4.0039 0.33594 1.1523-0.33203 2.3633-1.4844 2.6953-1.1523 0.33594-2.3633-0.33203-2.6953-1.4844-0.4375-1.4922-0.7695-3.0195-1-4.6016-0.22656-1.6016-0.34375-3.1914-0.34375-4.7852v-13.27zm61.309 26.348c-4.2383 1.9961-8.9023 3.7773-13.891 5.2656-1.8242 0.54297-3.7695 1.0664-5.8359 1.5625-9.3398 2.2461-18.453 3.1836-26.578 2.957 1.9766 1.7656 4.1797 3.3281 6.5547 4.6641 3.8906 2.1875 8.2344 3.7461 12.82 4.5391 6.9492-1.2031 13.328-4.1484 18.398-8.3594 3.5781-2.9688 6.5078-6.5703 8.5312-10.629z"/>
</svg>
`;

// protocol:version:scheme:payload
const PREFIX = "qcord:v1:b64:";
// Standard Base64: groups of 4 chars, optional "=" / "==" padding on the last group only.
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

const MESSAGE_SELECTOR = '[id^="message-content-"]';
const BUTTON_SELECTOR = ".qcord-button";
const DECODED_SELECTOR = ".qcord-plain";
// Continue reading timestamped .txt attachments from earlier Qcord versions.
const FILE_NAME_RE = /\.qcord$|^qcord_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt$/i;
const MAX_DECODED_FILE_SIZE = 1024 * 1024;
const PLUGIN_CSS = `
    [class*="channelTextArea"]:has(.qcord-button[data-encoding="true"]) [class*="scrollableContainer"] {
        background: linear-gradient(to top, rgba(23, 54, 83, .92), rgba(19, 29, 44, .88));
        backdrop-filter: blur(10px);
        box-shadow: inset 0 0 0 1px rgba(75, 160, 240, .5);
    }
    [class*="channelTextArea"]:has(.qcord-button[data-encoding="true"]) [role="textbox"] {
        color: #f1f6ff;
        caret-color: #8bc8ff;
    }
    [class*="channelTextArea"]:has(.qcord-button[data-encoding="true"]) :is([class*="placeholder"], [data-slate-placeholder]) {
        color: #b7c9df;
        opacity: 1;
    }
    .qcord-button {

        --qcord-icon-off: #c5c6ca;
        --qcord-icon-on: #ffffff;
        --qcord-accent: #2786de;
        
        display: inline-flex; 
        align-items: center; 
        justify-content: center;

        align-self: center; 
        flex-shrink: 0; 
        margin: 0;
        
        width: 32px; 
        height: 32px; 
        margin-left: 2px;

        padding: 4px 4px; 
        
        box-sizing: border-box;
        border: 0; 
        border-radius: 25%; 
        cursor: pointer;
        
        background: transparent; 
        color: var(--qcord-icon-off);
    }

    
    .qcord-button:focus-visible { outline: 2px solid var(--text-link); }
    .qcord-button:hover { color: var(--qcord-icon-on); }
    .qcord-button[data-decoding="true"] {
        color: var(--qcord-icon-on);
        background: linear-gradient(to top, var(--qcord-accent), transparent);
    }
    .qcord-button svg {
        display: block; 
        flex-shrink: 0;
        width: 22px; 
        height: 22px;
        
        transform: translateY(-2px) translateX(0.5px);

        
        fill: currentColor; 
        
        pointer-events: none;
        transition: transform 180ms ease;
    }
    .qcord-button:hover svg { 
        transform: translateY(-2px) translateX(0.5px) scale(1.075);

    }

    @media (prefers-reduced-motion: reduce) {
        .qcord-button svg { transition: none; }
    }

    .qcord-decoded > :not(.qcord-plain) { display: none !important; }
    .qcord-plain { white-space: pre-wrap; }
    .qcord-file-hidden { display: none !important; }
    .qcord-file-plain { color: #fff; font-size: 16px; line-height: 1.375; overflow-wrap: anywhere; }
    .qcord-panel { display: grid; gap: 12px; }
    .qcord-panel label { display: flex; align-items: center; gap: 8px; }
    .qcord-panel .qcord-field { display: grid; gap: 6px; }
    .qcord-panel input[type="checkbox"] { accent-color: #2786de; }
    .qcord-panel select, .qcord-panel button, .qcord-panel textarea {
        padding: 8px; border: 1px solid var(--background-modifier-accent);
        border-radius: 6px; background: var(--background-secondary);
        color: var(--text-normal); font: inherit;
    }
    .qcord-panel select, .qcord-panel textarea { width: 100%; box-sizing: border-box; }
    .qcord-panel select { color-scheme: dark; }
    .qcord-panel select, .qcord-panel option { background: #172638; color: #f1f6ff; }
    .qcord-panel pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; }
    .qcord-panel textarea { font-family: monospace; }
    .qcord-panel button { cursor: pointer; }
    .qcord-panel button:disabled { opacity: .5; cursor: default; }
    .qcord-panel p { margin: 0; color: var(--text-muted); font-size: 12px; }
`;

module.exports = class Qcord {
    start() {
        this.enabled = BdApi.Data.load(KEY_STORE, "enabled") === true;
        this.decodeIncoming = BdApi.Data.load(KEY_STORE, "decodeIncoming") !== false;
        this.running = false;
        this.frame = null;
        this.session = {};
        this.fileDecodes = new WeakMap();
        this.renderedMessages = new Map();
        this.markdown = BdApi.Webpack.getByKeys("parse", "reactParserFor");
        this.markupClass = BdApi.Webpack.getByKeys("markup")?.markup || "";
        this.keys = null;
        this.keyPairs = new Map();
        this.keyTasks = new Map();
        this.metrics = {};
        this.schemeStatus = {};
        const savedScheme = BdApi.Data.load(KEY_STORE, "scheme");
        this.scheme = KEM_SCHEMES.includes(savedScheme) ? savedScheme : "ml-kem-768";

        // Discord internals are not a stable API. Do not present a working switch
        // unless we can actually intercept ordinary chat submissions.
        const actions = BdApi.Webpack.getByKeys("sendMessage", "editMessage");
        if (!actions || typeof actions.sendMessage !== "function") {
            BdApi.UI.showToast("Qcord could not find Discord's send function. Encryption is unavailable.", {type: "error"});
            return;
        }

        const unpatch = BdApi.Patcher.instead(NAME, actions, "sendMessage", (context, args, original) => {
            if (!this.enabled) return original.apply(context, args);

            try {
                const message = args[1];
                if (!message || typeof message.content !== "string") {
                    return this.blockSend("Qcord blocked sending: unrecognized message format.");
                }
                if (message.content) {
                    return this.prepareMessageFile(args[0], message.content);
                }
            }
            catch {
                // Never fall back to sending plaintext if conversion fails.
                return this.blockSend("Qcord blocked sending because encryption failed.");
            }
            // An empty composer can submit the staged file without creating another.
            return original.apply(context, args);
        });

        if (typeof unpatch !== "function") {
            BdApi.UI.showToast("Qcord could not install its send hook. Encryption is unavailable.", {type: "error"});
            return;
        }
        this.running = true;
        BdApi.DOM.addStyle(NAME, PLUGIN_CSS);
        if (!this.markdown) {
            BdApi.UI.showToast("Qcord could not find Discord's Markdown renderer. Decoded messages will display as plain text.", {type: "warning"});
        }
        this.mountButtons();
        this.scanMessages();
        BdApi.UI.showToast("Qcord ready - open the shield for settings.", {type: "success"});
    }

    // Base64 via Node's Buffer (Node core, same runtime as `crypto`).
    // Note: Node's crypto module has no Base64 primitive; Buffer is the built-in for it.
    encodeText(text) {
        return text ? PREFIX + Buffer.from(text, "utf8").toString("base64") : "";
    }

    // Returns the decoded string, or null if `text` is not a valid Qcord Base64 message.
    // Strict on purpose, so ordinary chat is never misread as ciphertext.
    decodeText(text) {
        if (typeof text !== "string") return null;
        if (!text.startsWith(PREFIX)) return null;
        const payload = text.slice(PREFIX.length);
        // Base64 output length is always a multiple of 4 ("=" / "==" pad the last group).
        if (!payload || payload.length % 4 !== 0 || !BASE64_RE.test(payload)) return null;
        try {
            const bytes = Buffer.from(payload, "base64");
            // Canonical check: re-encoding must reproduce the input exactly.
            if (bytes.toString("base64") !== payload) return null;
            return new TextDecoder("utf-8", {fatal: true}).decode(bytes);
        }
        catch {
            return null;
        }
    }

    blockSend(reason) {
        BdApi.UI.showToast(reason, {type: "error"});
        // Discord's normal send result instructs the composer whether to clear
        // the draft. Resolve without calling the original send function.
        return Promise.resolve({shouldClear: false, shouldRefocus: true});
    }

    async prepareMessageFile(channelId, text) {
        const session = this.session;
        try {
            const content = await this.encryptMessage(channelId, text);
            if (!this.running || !this.enabled || this.session !== session) throw new Error("Qcord encryption was stopped.");
            return await this.stageMessageFile(channelId, content);
        }
        catch (error) {
            return this.blockSend(`Qcord did not send your message: ${error.message}`);
        }
    }

    async stageMessageFile(channelId, content) {
        try {
            const attachments = BdApi.Webpack.getByKeys("addFiles");
            if (typeof attachments?.addFiles !== "function") {
                return this.blockSend("Qcord could not find attachment staging. Your message was not sent.");
            }
            const now = new Date();
            const parts = [now.getFullYear(), now.getMonth() + 1, now.getDate(), now.getHours(), now.getMinutes(), now.getSeconds()]
                .map(value => String(value).padStart(2, "0"));
            const filename = `${parts.slice(0, 3).join("-")}_${parts.slice(3).join("-")}.qcord`;
            const file = new File([content], filename, {type: "application/octet-stream"});
            // Stage the encoded envelope for review; never send the plaintext draft.
            await attachments.addFiles({
                channelId, draftType: 0, showLargeMessageDialog: false,
                files: [{file, platform: 1, isThumbnail: false}]
            });
            const timing = this.metrics.encrypt;
            BdApi.UI.showToast(`Qcord attached your encrypted message${timing ? ` (${timing.ms.toFixed(3)} ms, ${file.size} bytes)` : ""}. Press Send.`, {type: "success"});
            return {shouldClear: true, shouldRefocus: true};
        }
        catch {
            return this.blockSend("Qcord could not prepare the message attachment. Your message was not sent.");
        }
    }

    setEnabled(enabled) {
        if (!this.running) return;
        BdApi.Data.save(KEY_STORE, "enabled", Boolean(enabled));
        this.enabled = Boolean(enabled);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) this.updateButton(button);
    }

    setDecoding(enabled) {
        if (!this.running) return;
        BdApi.Data.save(KEY_STORE, "decodeIncoming", Boolean(enabled));
        this.decodeIncoming = Boolean(enabled);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) this.updateButton(button);
        this.scanMessages();
    }

    clearDecoded() {
        for (const span of this.renderedMessages.keys()) this.removeDecoded(span);
        for (const span of document.querySelectorAll(DECODED_SELECTOR)) this.removeDecoded(span);
        for (const element of document.querySelectorAll(".qcord-decoded")) element.classList.remove("qcord-decoded");
        for (const element of document.querySelectorAll(".qcord-file-hidden")) element.classList.remove("qcord-file-hidden");
    }

    renderDecoded(element, text) {
        const previous = this.renderedMessages.get(element);
        if (previous?.text === text) return;
        let root = previous?.root;
        try {
            if (this.markdown) {
                const content = this.markdown.parse(text, true, {allowLinks: true});
                root ||= BdApi.ReactDOM.createRoot(element);
                root.render(content);
            }
            else element.textContent = text;
        }
        catch (error) {
            root?.unmount();
            root = null;
            element.textContent = text;
            BdApi.Logger.warn(NAME, "Could not format a decoded message.", error);
        }
        this.renderedMessages.set(element, {root, text});
    }

    removeDecoded(element) {
        this.renderedMessages.get(element)?.root?.unmount();
        this.renderedMessages.delete(element);
        element.remove();
    }

    updateButton(button) {
        const encoding = String(this.enabled);
        const decoding = String(this.decodeIncoming);
        if (button.getAttribute("data-encoding") === encoding && button.getAttribute("data-decoding") === decoding) return;
        button.setAttribute("data-encoding", encoding);
        button.setAttribute("data-decoding", decoding);
        button.title = `Qcord settings - Encryption ${this.enabled ? "on" : "off"}, decryption ${this.decodeIncoming ? "on" : "off"}`;
        button.setAttribute("aria-label", button.title);
    }

    mountButtons() {
        if (!this.running) return;
        // Place Qcord first in the right-hand controls, before Discord's buttons.
        // Class fragments avoid depending on Discord's changing CSS hashes.
        for (const editor of document.querySelectorAll('[role="textbox"][contenteditable="true"]')) {
            const composer = editor.closest('[class*="channelTextArea"]');
            if (!composer) continue;
            const controls = composer.querySelector('[class*="buttons_"]');
            if (!controls) continue;
            let button = composer.querySelector(BUTTON_SELECTOR);
            if (!button) {
                button = document.createElement("button");
                button.type = "button";
                button.className = "qcord-button";
                button.setAttribute("aria-haspopup", "dialog");
                button.innerHTML = BUTTON_SVG;
                button.addEventListener("mousedown", event => event.preventDefault());
                button.addEventListener("click", event => {
                    event.preventDefault();
                    event.stopPropagation();
                    BdApi.UI.alert(NAME, this.getSettingsPanel());
                });
            }
            this.updateButton(button);
            if (controls.firstElementChild !== button) controls.prepend(button);
        }
    }

    // Read visible chat messages and decode any that carry the Qcord prefix.
    // Idempotent: safe to run on every DOM mutation. The original React-owned
    // nodes are hidden, never edited; Discord's Markdown renderer owns our nodes.
    scanMessages() {
        if (!this.running) return;
        if (!this.decodeIncoming) { this.clearDecoded(); return; }
        for (const element of this.renderedMessages.keys()) {
            if (!element.isConnected) this.removeDecoded(element);
        }
        for (const element of document.querySelectorAll(MESSAGE_SELECTOR)) {
            let span = element.querySelector(`:scope > ${DECODED_SELECTOR}`);
            const source = Array.from(element.childNodes)
                .filter(node => node !== span)
                .map(node => node.textContent)
                .join("");
            const decoded = this.decodeText(source);
            if (decoded === null) {
                if (span) {
                    this.removeDecoded(span);
                    element.classList.remove("qcord-decoded");
                }
                continue;
            }
            if (!span) {
                span = document.createElement("div");
                span.className = `qcord-plain ${this.markupClass}`;
                span.title = "Decoded from Qcord Base64 (encoded, not encrypted)";
                element.append(span);
            }
            this.renderDecoded(span, decoded);
            element.classList.add("qcord-decoded");
        }
        for (const link of document.querySelectorAll('[id^="chat-messages-"] a[href]')) {
            this.decodeFile(link);
        }
    }

    async decodeFile(link) {
        if (!this.running || !this.decodeIncoming) return;
        let url;
        try { url = new URL(link.href); }
        catch { return; }
        if (url.protocol !== "https:" || url.port || url.username || url.password ||
            !["cdn.discordapp.com", "media.discordapp.net"].includes(url.hostname) ||
            !/^\/attachments\/\d+\/\d+\//.test(url.pathname)) return;
        if (!FILE_NAME_RE.test(url.pathname.split("/").pop())) return;
        // Discord renders .txt uploads as text previews as well as ordinary file
        // cards. Hide the outer attachment item so its preview leaves no blank tile.
        const card = link.closest('[class*="mosaicItem_"]') || link.closest(
            '[class*="textContainer_"], [class*="fileWrapper_"], [class*="file_"], [class*="attachment_"]'
        );
        if (!card) return;
        let state = this.fileDecodes.get(card);
        if (state && state.url !== url.href) {
            if (state.span) this.removeDecoded(state.span);
            card.classList.remove("qcord-file-hidden");
            this.fileDecodes.delete(card);
            state = null;
        }
        if (!state) {
            state = {url: url.href, decoded: null, pending: true};
            this.fileDecodes.set(card, state);
            const session = this.session;
            try {
                // Use BetterDiscord's native fetch; signed CDN URLs need no auth token.
                const response = await BdApi.Net.fetch(url.href, {timeout: 10000, redirect: "error", maxRedirects: 0});
                if (!response.ok) return;
                // ponytail: 1 MiB display ceiling; streaming download limits need a streaming Net API.
                if (Number(response.headers.get("content-length")) > MAX_DECODED_FILE_SIZE) return;
                const text = await response.text();
                if (text.length > MAX_DECODED_FILE_SIZE || this.session !== session) return;
                const channelId = link.closest('[id^="chat-messages-"]')?.id?.match(/^chat-messages-(\d+)-\d+$/)?.[1];
                state.encrypted = text.startsWith(ENCRYPTED_PREFIX);
                const started = performance.now();
                state.decoded = await this.decryptMessage(text, channelId);
                state.decryptMs = state.encrypted ? performance.now() - started : null;
                if (this.session !== session) return;
            }
            catch (error) {
                // Keep the original attachment available if download/decoding fails.
                BdApi.Logger.warn(NAME, "Could not decode a Qcord attachment.", error);
            }
            finally { state.pending = false; }
        }
        if (state.pending || state.decoded === null || !this.running || !this.decodeIncoming ||
            !card.isConnected || link.href !== state.url || this.fileDecodes.get(card) !== state) return;
        if (!state.span?.isConnected) {
            state.span = document.createElement("div");
            state.span.className = `qcord-plain qcord-file-plain ${this.markupClass}`;
            state.span.title = state.encrypted ? `Decrypted locally by Qcord in ${state.decryptMs?.toFixed(3)} ms (ML-KEM + AES-256-GCM)` : "Decoded from Qcord Base64 attachment (encoded, not encrypted)";
            card.after(state.span);
            this.renderDecoded(state.span, state.decoded);
        }
        card.classList.add("qcord-file-hidden");
    }

    async generateKeys(scheme) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (!SCHEMES.includes(scheme)) throw new Error("Unknown key algorithm.");
        if (!Crypto?.generateKeyPair) throw new Error("This Discord runtime does not expose native key generation.");
        if (this.keyPairs.has(scheme)) return this.keyPairs.get(scheme);
        if (this.keyTasks.has(scheme)) return this.keyTasks.get(scheme);
        const session = this.session;
        const task = (async () => {
            const stored = BdApi.Data.load(KEY_STORE, "keyPairs") || {};
            if (typeof stored !== "object" || Array.isArray(stored)) throw new Error("Invalid saved key configuration.");
            let keys;
            if (stored[scheme]) {
                const {publicKey, privateKey, keygenMs} = stored[scheme];
                keys = {scheme, publicKey: Crypto.createPublicKey(publicKey), privateKey: Crypto.createPrivateKey(privateKey), keygenMs};
                if (keys.publicKey.asymmetricKeyType !== scheme || keys.privateKey.asymmetricKeyType !== scheme ||
                    !Crypto.createPublicKey(keys.privateKey).equals(keys.publicKey)) {
                    throw new Error("Saved keys do not match. Restore your key configuration from backup.");
                }
            }
            else {
                const started = performance.now();
                keys = await new Promise((resolve, reject) => {
                    Crypto.generateKeyPair(scheme, {}, (error, publicKey, privateKey) => {
                        if (error) reject(error);
                        else resolve({scheme, publicKey, privateKey, keygenMs: performance.now() - started});
                    });
                });
                if (!this.running || this.session !== session) throw new Error("Qcord stopped during key generation.");
                // Reload so concurrent generation of different schemes preserves both.
                BdApi.Data.save(KEY_STORE, "keyPairs", {
                    ...(BdApi.Data.load(KEY_STORE, "keyPairs") || {}),
                    [scheme]: {
                        publicKey: keys.publicKey.export({type: "spki", format: "pem"}),
                        privateKey: keys.privateKey.export({type: "pkcs8", format: "pem"}),
                        keygenMs: keys.keygenMs, createdAt: new Date().toISOString()
                    }
                });
            }
            if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
            this.keyPairs.set(scheme, keys);
            this.keys = keys;
            this.schemeStatus[scheme] = "Key API passed";
            this.metrics.keygen = {scheme, ms: keys.keygenMs,
                publicBytes: keys.publicKey.export({type: "spki", format: "der"}).length,
                privateBytes: keys.privateKey.export({type: "pkcs8", format: "der"}).length};
            return keys;
        })();
        this.keyTasks.set(scheme, task);
        try { return await task; }
        catch (error) {
            if (this.session === session) this.schemeStatus[scheme] = error.message;
            throw error;
        }
        finally { if (this.keyTasks.get(scheme) === task) this.keyTasks.delete(scheme); }
    }

    keyId(publicKey) {
        return Crypto.createHash("sha256").update(publicKey.export({type: "spki", format: "der"})).digest("hex");
    }

    saveRecipients(channelId, text, scheme) {
        if (!/^\d+$/.test(channelId || "")) throw new Error("Open a Discord channel first.");
        if (!KEM_SCHEMES.includes(scheme)) throw new Error("Choose an ML-KEM encryption scheme.");
        const pems = text.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) || [];
        if (text.replace(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g, "").trim() || pems.length > 15) {
            throw new Error("Paste up to 15 public PEM keys, without other text.");
        }
        for (const pem of pems) {
            if (Crypto.createPublicKey(pem).asymmetricKeyType !== scheme) throw new Error("Every recipient key must use the selected ML-KEM scheme.");
        }
        const recipients = BdApi.Data.load(KEY_STORE, "recipients") || {};
        BdApi.Data.save(KEY_STORE, "recipients", {...recipients, [channelId]: {scheme, publicKeys: pems}});
    }

    decodeBytes(value, size) {
        if (typeof value !== "string" || value.length > MAX_DECODED_FILE_SIZE || !BASE64_RE.test(value)) throw new Error("Invalid encrypted file field.");
        const bytes = Buffer.from(value, "base64");
        if (bytes.toString("base64") !== value || (size !== undefined && bytes.length !== size)) throw new Error("Invalid encrypted file field.");
        return bytes;
    }

    seal(data, key, aad) {
        const iv = Crypto.randomBytes(12);
        const cipher = Crypto.createCipheriv("aes-256-gcm", key, iv);
        cipher.setAAD(aad);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return {iv: iv.toString("base64"), data: encrypted.toString("base64"), tag: cipher.getAuthTag().toString("base64")};
    }

    openSealed(sealed, key, aad) {
        const decipher = Crypto.createDecipheriv("aes-256-gcm", key, this.decodeBytes(sealed.iv, 12));
        decipher.setAAD(aad);
        decipher.setAuthTag(this.decodeBytes(sealed.tag, 16));
        return Buffer.concat([decipher.update(this.decodeBytes(sealed.data)), decipher.final()]);
    }

    wrappingKey(sharedSecret) {
        return Crypto.hkdfSync("sha256", sharedSecret, Buffer.alloc(0), Buffer.from("Qcord v2 key wrap"), 32);
    }

    async encryptMessage(channelId, text) {
        if (!Crypto?.encapsulate || !Crypto?.decapsulate) throw new Error("Discord's crypto runtime lacks ML-KEM encapsulation/decapsulation.");
        if (!/^\d+$/.test(channelId || "")) throw new Error("Invalid channel.");
        const scheme = this.scheme;
        const recipients = BdApi.Data.load(KEY_STORE, "recipients")?.[channelId];
        if (recipients?.scheme !== scheme || !Array.isArray(recipients.publicKeys) || !recipients.publicKeys.length) {
            throw new Error("Save recipient public keys for this channel and scheme in Qcord settings first.");
        }
        if (recipients.publicKeys.length > 15) throw new Error("At most 15 recipient keys are supported.");
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Message is too large for a Qcord file.");
        const session = this.session;
        const ownKeys = await this.generateKeys(scheme);
        const publicKeys = new Map();
        for (const key of [ownKeys.publicKey, ...recipients.publicKeys.map(pem => Crypto.createPublicKey(pem))]) {
            if (key.asymmetricKeyType !== scheme) throw new Error("Recipient key algorithm does not match.");
            publicKeys.set(this.keyId(key), key);
        }
        const started = performance.now();
        const aad = Buffer.from(JSON.stringify({scheme, channelId, recipientIds: [...publicKeys.keys()]}));
        const payloadKey = Crypto.randomBytes(32);
        const envelopes = [];
        for (const [id, publicKey] of publicKeys) {
            const {sharedKey, ciphertext} = await new Promise((resolve, reject) =>
                Crypto.encapsulate(publicKey, (error, result) => error ? reject(error) : resolve(result)));
            envelopes.push({id, kem: ciphertext.toString("base64"),
                ...this.seal(payloadKey, this.wrappingKey(sharedKey), Buffer.concat([aad, Buffer.from(id)]))});
        }
        const output = ENCRYPTED_PREFIX + JSON.stringify({scheme, channelId, recipients: envelopes, ...this.seal(input, payloadKey, aad)});
        const fileBytes = Buffer.byteLength(output);
        if (fileBytes > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file exceeds the 1 MiB display limit. Shorten your message.");
        if (!this.running || !this.enabled || this.session !== session) throw new Error("Qcord encryption was stopped.");
        this.metrics.encrypt = {scheme, ms: performance.now() - started, inputBytes: input.length, fileBytes, recipients: envelopes.length};
        return output;
    }

    async decryptMessage(text, channelId) {
        if (!text.startsWith(ENCRYPTED_PREFIX)) return this.decodeText(text);
        if (!Crypto?.decapsulate) throw new Error("Discord's crypto runtime lacks ML-KEM decapsulation.");
        if (Buffer.byteLength(text) > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file is too large.");
        const started = performance.now();
        const session = this.session;
        const file = JSON.parse(text.slice(ENCRYPTED_PREFIX.length));
        if (!file || !KEM_SCHEMES.includes(file.scheme) || !/^\d+$/.test(channelId || "") || file.channelId !== channelId ||
            !Array.isArray(file.recipients) || !file.recipients.length || file.recipients.length > 16) throw new Error("Invalid encrypted file or wrong channel.");
        const ids = file.recipients.map(recipient => recipient?.id);
        if (ids.some(id => typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id)) || new Set(ids).size !== ids.length) throw new Error("Invalid recipient list.");
        // Incoming files must never create new identities.
        if (!this.keyPairs.has(file.scheme) && !BdApi.Data.load(KEY_STORE, "keyPairs")?.[file.scheme]) throw new Error("No saved private key for this file.");
        const keys = await this.generateKeys(file.scheme);
        const id = this.keyId(keys.publicKey);
        const recipient = file.recipients.find(entry => entry.id === id);
        if (!recipient) throw new Error("This file is not addressed to your key.");
        const aad = Buffer.from(JSON.stringify({scheme: file.scheme, channelId, recipientIds: ids}));
        const sharedKey = await new Promise((resolve, reject) =>
            Crypto.decapsulate(keys.privateKey, this.decodeBytes(recipient.kem), (error, result) => error ? reject(error) : resolve(result)));
        const payloadKey = this.openSealed(recipient, this.wrappingKey(sharedKey), Buffer.concat([aad, Buffer.from(id)]));
        if (payloadKey.length !== 32) throw new Error("Invalid payload key.");
        const plaintext = this.openSealed(file, payloadKey, aad);
        const decoded = new TextDecoder("utf-8", {fatal: true}).decode(plaintext);
        if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
        this.metrics.decrypt = {scheme: file.scheme, ms: performance.now() - started, inputBytes: plaintext.length, fileBytes: Buffer.byteLength(text)};
        return decoded;
    }

    async testScheme(scheme, text) {
        const keys = await this.generateKeys(scheme);
        const session = this.session;
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Test input exceeds 1 MiB.");
        let started = performance.now();
        let result;
        if (KEM_SCHEMES.includes(scheme)) {
            if (!Crypto.encapsulate || !Crypto.decapsulate) throw new Error("This runtime cannot perform ML-KEM encapsulation.");
            const encrypted = await new Promise((resolve, reject) =>
                Crypto.encapsulate(keys.publicKey, (error, value) => error ? reject(error) : resolve(value)));
            const encapsulateMs = performance.now() - started;
            started = performance.now();
            const sharedKey = await new Promise((resolve, reject) =>
                Crypto.decapsulate(keys.privateKey, encrypted.ciphertext, (error, value) => error ? reject(error) : resolve(value)));
            if (!Crypto.timingSafeEqual(encrypted.sharedKey, sharedKey)) throw new Error("KEM round-trip failed.");
            result = {scheme, encapsulateMs, decapsulateMs: performance.now() - started, kemBytes: encrypted.ciphertext.length};
        }
        else {
            const signature = await new Promise((resolve, reject) =>
                Crypto.sign(null, input, keys.privateKey, (error, value) => error ? reject(error) : resolve(value)));
            const signMs = performance.now() - started;
            started = performance.now();
            const valid = await new Promise((resolve, reject) =>
                Crypto.verify(null, input, keys.publicKey, signature, (error, value) => error ? reject(error) : resolve(value)));
            if (!valid) throw new Error("Signature verification failed.");
            result = {scheme, signMs, verifyMs: performance.now() - started, inputBytes: input.length, signatureBytes: signature.length};
        }
        if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
        this.schemeStatus[scheme] = "Round-trip passed";
        this.metrics.test = result;
        return result;
    }

    getSettingsPanel() {
        const plugin = this;
        const {createElement: h, useState, useEffect} = BdApi.React;
        const channelId = BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId();
        const savedRecipients = BdApi.Data.load(KEY_STORE, "recipients")?.[channelId];
        const versions = typeof process === "object" ? process.versions || {} : {};
        const canGenerate = typeof Crypto?.generateKeyPair === "function";
        return h(function Panel() {
            const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
            const [decoding, setDecoding] = useState(plugin.decodeIncoming !== false);
            const [scheme, setScheme] = useState(plugin.scheme);
            const [testAlgorithm, setTestAlgorithm] = useState(plugin.scheme);
            const [publicKey, setPublicKey] = useState("");
            const [recipientText, setRecipientText] = useState(savedRecipients?.scheme === plugin.scheme ? savedRecipients.publicKeys.join("\n") : "");
            const [sample, setSample] = useState("Qcord PQC round-trip test");
            const [busy, setBusy] = useState(true);
            const [status, setStatus] = useState("Loading or generating your encryption key...");
            const [elapsed, setElapsed] = useState(0);
            useEffect(() => {
                let active = true;
                plugin.generateKeys(plugin.scheme).then(keys => {
                    if (active) {
                        setPublicKey(keys.publicKey.export({type: "spki", format: "pem"}));
                        setStatus("Encryption key ready and saved locally.");
                    }
                }).catch(error => {
                    if (active) setStatus(error.message);
                }).finally(() => { if (active) setBusy(false); });
                return () => { active = false; };
            }, []);
            useEffect(() => {
                if (!busy) return;
                const started = performance.now();
                setElapsed(0);
                const timer = setInterval(() => setElapsed(performance.now() - started), 100);
                return () => clearInterval(timer);
            }, [busy]);
            const loadKeys = async value => {
                setBusy(true); setStatus("Loading or generating encryption keys...");
                try {
                    const keys = await plugin.generateKeys(value);
                    setPublicKey(keys.publicKey.export({type: "spki", format: "pem"}));
                    setStatus("Encryption key ready and saved locally.");
                }
                catch (error) { setPublicKey(""); setStatus(error.message); }
                finally { setBusy(false); }
            };
            const runTests = async algorithms => {
                setBusy(true);
                for (const algorithm of algorithms) {
                    if (!plugin.running) break;
                    setStatus("Testing " + algorithm.toUpperCase() + "...");
                    try { await plugin.testScheme(algorithm, sample); }
                    catch (error) { plugin.schemeStatus[algorithm] = error.message; }
                }
                setStatus("Tests finished. See algorithm results below."); setBusy(false);
            };
            const metrics = plugin.metrics;
            const ms = value => Number.isFinite(value) ? value.toFixed(3) + " ms" : "not measured";
            const timingLines = [];
            if (metrics.keygen) timingLines.push("Key generation (saved measurement): " + metrics.keygen.scheme + ", " + ms(metrics.keygen.ms) +
                "; public " + metrics.keygen.publicBytes + " B, private " + metrics.keygen.privateBytes + " B (DER)");
            if (metrics.encrypt) timingLines.push("Last encryption: " + ms(metrics.encrypt.ms) + "; " + metrics.encrypt.inputBytes + " B text -> " + metrics.encrypt.fileBytes + " B file; " + metrics.encrypt.recipients + " keys");
            if (metrics.decrypt) timingLines.push("Last decryption: " + ms(metrics.decrypt.ms) + "; " + metrics.decrypt.fileBytes + " B file -> " + metrics.decrypt.inputBytes + " B text");
            if (metrics.test?.encapsulateMs !== undefined) timingLines.push("Last KEM test: " + metrics.test.scheme + "; encapsulate " + ms(metrics.test.encapsulateMs) + ", decapsulate " + ms(metrics.test.decapsulateMs) + "; " + metrics.test.kemBytes + " B KEM ciphertext");
            if (metrics.test?.signMs !== undefined) timingLines.push("Last signature test: " + metrics.test.scheme + "; sign " + ms(metrics.test.signMs) + ", verify " + ms(metrics.test.verifyMs) + "; " + metrics.test.signatureBytes + " B signature for " + metrics.test.inputBytes + " B input");
            return h("div", {className: "qcord-panel"},
                h("label", null, h("input", {
                    type: "checkbox", checked: enabled, disabled: !plugin.running,
                    onChange: event => { plugin.setEnabled(event.target.checked); setEnabled(plugin.enabled); }
                }), "Encrypt outgoing messages"),
                h("label", null, h("input", {
                    type: "checkbox", checked: decoding, disabled: !plugin.running,
                    onChange: event => { plugin.setDecoding(event.target.checked); setDecoding(plugin.decodeIncoming); }
                }), "Decrypt incoming messages (also decode older Base64)"),
                h("p", null, "Runtime: Node " + (versions.node || "unavailable") + "; OpenSSL " + (versions.openssl || "unavailable") +
                    "; crypto " + (Crypto ? "loaded" : "unavailable") + "; KEM API " + (Crypto?.encapsulate && Crypto?.decapsulate ? "available" : "unavailable")),
                h("label", {className: "qcord-field"}, "Chat encryption scheme", h("select", {
                    value: scheme, disabled: busy || !plugin.running,
                    onChange: event => {
                        const value = event.target.value;
                        plugin.scheme = value; BdApi.Data.save(KEY_STORE, "scheme", value); setScheme(value);
                        const recipients = BdApi.Data.load(KEY_STORE, "recipients")?.[channelId];
                        setRecipientText(recipients?.scheme === value ? recipients.publicKeys.join("\n") : "");
                        loadKeys(value);
                    }
                }, ...KEM_SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase())))),
                h("button", {type: "button", disabled: busy || !plugin.running || !canGenerate, onClick: () => loadKeys(scheme)}, "Load/generate my encryption key"),
                publicKey && h("label", {className: "qcord-field"}, "My public encryption key (share this)", h("textarea", {readOnly: true, rows: 4, value: publicKey})),
                publicKey && h("p", null, "SHA-256 fingerprint: " + plugin.keyId(Crypto.createPublicKey(publicKey))),
                h("label", {className: "qcord-field"}, "Recipient public keys for channel " + (channelId || "(none selected)"), h("textarea", {
                    rows: 4, value: recipientText, disabled: busy || !channelId,
                    placeholder: "Paste each recipient's complete PUBLIC KEY PEM block here.",
                    onChange: event => setRecipientText(event.target.value)
                })),
                h("button", {type: "button", disabled: busy || !channelId || !Crypto,
                    onClick: () => {
                        try { plugin.saveRecipients(channelId, recipientText, scheme); setStatus("Recipient keys saved for this channel."); }
                        catch (error) { setStatus(error.message); }
                    }
                }, "Save recipient keys"),
                h("p", null, "Verify public-key fingerprints with your recipients before saving. Use the same ML-KEM scheme. Your own key is included automatically so you can read sent files."),
                h("p", null, "Private keys are saved unencrypted in local qcord.config.json. Keep that file private and backed up. These experimental files do not authenticate the sender's identity."),
                h("label", {className: "qcord-field"}, "Native PQC algorithm test", h("select", {
                    value: testAlgorithm, disabled: busy,
                    onChange: event => setTestAlgorithm(event.target.value)
                }, ...SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase() + (KEM_SCHEMES.includes(value) ? " (KEM)" : " (signature)"))))),
                h("label", {className: "qcord-field"}, "Signature test text", h("textarea", {rows: 2, value: sample, disabled: busy, onChange: event => setSample(event.target.value)})),
                h("button", {type: "button", disabled: busy || !plugin.running || !canGenerate, onClick: () => runTests([testAlgorithm])}, "Test selected algorithm"),
                h("button", {type: "button", disabled: busy || !plugin.running || !canGenerate, onClick: () => runTests(SCHEMES)}, "Test all listed algorithms"),
                h("div", {role: "status"}, busy ? status + " " + elapsed.toFixed(0) + " ms elapsed" : status),
                h("pre", null, SCHEMES.map(value => value + ": " + (plugin.schemeStatus[value] || "not tested")).join("\n")),
                h("pre", null, timingLines.join("\n") || "No timings yet."),
                h("p", null, "Timings are local elapsed milliseconds, including async scheduling. Encryption excludes key generation; decryption excludes download. CPU clock cycles are unavailable through this JavaScript API."),
                h("p", null, "ML-KEM, ML-DSA and SLH-DSA are standardized PQC families. Candidates such as HQC/Falcon require implementations beyond this native-only plugin. Signature tests do not encrypt text.")
            );
        });
    }

    // BetterDiscord's lifecycle supplies DOM mutations and navigation events.
    observer() { this.scheduleMount(); }
    onSwitch() { this.scheduleMount(); }

    scheduleMount() {
        if (!this.running || this.frame !== null) return;
        this.frame = requestAnimationFrame(() => {
            this.frame = null;
            this.mountButtons();
            this.scanMessages();
        });
    }

    stop() {
        this.running = false;
        this.keys = null;
        this.keyPairs.clear();
        this.keyTasks.clear();
        this.session = null;
        if (this.frame !== null && this.frame !== undefined) cancelAnimationFrame(this.frame);
        this.frame = null;
        BdApi.Patcher.unpatchAll(NAME);
        BdApi.DOM.removeStyle(NAME);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) button.remove();
        this.clearDecoded(); //test
    }
};
