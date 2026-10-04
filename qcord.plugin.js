/**
 * @name Qcord
 * @author Eric, Arsh, Yasser
 * @authorId 215269534540496896
 * @version 0.0.1
 * @description Client-side Base64 message encoding with auto-decode of incoming Qcord messages, plus a post-quantum key-generation demo. Base64 is an encoding, NOT encryption.
 * @invite GSdMfMBW5g
 * @source https://github.com/EricZoop/qcord
 */

"use strict";

const NAME = "Qcord";
let Crypto;
try { Crypto = require("crypto"); }
catch { Crypto = null; } // Encoding still works if the optional key API is unavailable.
const SCHEMES = ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f"];
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
        position: relative;
    }
    [class*="channelTextArea"]:has(.qcord-button[data-encoding="true"]) [class*="scrollableContainer"]::after {
        content: "";
        position: absolute;
        inset: 0;
        padding: 2px;
        border-radius: inherit;
        background: linear-gradient(to top, #2786de, transparent);
        mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
        mask-composite: exclude;
        pointer-events: none;
        z-index: 1;
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
    .qcord-panel textarea { font-family: monospace; }
    .qcord-panel button { cursor: pointer; }
    .qcord-panel button:disabled { opacity: .5; cursor: default; }
    .qcord-panel p { margin: 0; color: var(--text-muted); font-size: 12px; }
`;

module.exports = class Qcord {
    start() {
        this.enabled = BdApi.Data.load(NAME, "enabled") === true;
        this.decodeIncoming = BdApi.Data.load(NAME, "decodeIncoming") !== false;
        this.running = false;
        this.frame = null;
        this.session = {};
        this.fileDecodes = new WeakMap();
        this.renderedMessages = new Map();
        this.markdown = BdApi.Webpack.getByKeys("parse", "reactParserFor");
        this.markupClass = BdApi.Webpack.getByKeys("markup")?.markup || "";
        this.keys = null;
        this.generating = false;
        const savedScheme = BdApi.Data.load(NAME, "scheme");
        this.scheme = SCHEMES.includes(savedScheme) ? savedScheme : "ml-kem-768";

        // Discord internals are not a stable API. Do not present a working switch
        // unless we can actually intercept ordinary chat submissions.
        const actions = BdApi.Webpack.getByKeys("sendMessage", "editMessage");
        if (!actions || typeof actions.sendMessage !== "function") {
            BdApi.UI.showToast("Qcord could not find Discord's send function. Encoding is unavailable.", {type: "error"});
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
                    return this.stageMessageFile(args[0], this.encodeText(message.content));
                }
            }
            catch {
                // Never fall back to sending plaintext if conversion fails.
                return this.blockSend("Qcord blocked sending because encoding failed.");
            }
            // An empty composer can submit the staged file without creating another.
            return original.apply(context, args);
        });

        if (typeof unpatch !== "function") {
            BdApi.UI.showToast("Qcord could not install its send hook. Encoding is unavailable.", {type: "error"});
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
            BdApi.UI.showToast("Qcord attached your encoded message. Review the file and press Send.", {type: "success"});
            return {shouldClear: true, shouldRefocus: true};
        }
        catch {
            return this.blockSend("Qcord could not prepare the message attachment. Your message was not sent.");
        }
    }

    setEnabled(enabled) {
        if (!this.running) return;
        BdApi.Data.save(NAME, "enabled", Boolean(enabled));
        this.enabled = Boolean(enabled);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) this.updateButton(button);
    }

    setDecoding(enabled) {
        if (!this.running) return;
        BdApi.Data.save(NAME, "decodeIncoming", Boolean(enabled));
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
        button.title = `Qcord settings - Encoding ${this.enabled ? "on" : "off"}, decoding ${this.decodeIncoming ? "on" : "off"}`;
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
                state.decoded = this.decodeText(text);
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
            state.span.title = "Decoded from Qcord Base64 attachment (encoded, not encrypted)";
            card.after(state.span);
            this.renderDecoded(state.span, state.decoded);
        }
        card.classList.add("qcord-file-hidden");
    }

    async generateKeys(scheme) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (!SCHEMES.includes(scheme)) throw new Error("Unknown key algorithm.");
        if (typeof Crypto?.generateKeyPair !== "function") {
            throw new Error("This BetterDiscord build does not expose native key generation. PQC requires a supported crypto API or a bundled JavaScript library.");
        }
        if (this.generating) throw new Error("Key generation is already running.");
        const session = this.session;
        this.generating = true;
        try {
            const keys = await new Promise((resolve, reject) => {
                Crypto.generateKeyPair(scheme, {}, (error, publicKey, privateKey) => {
                    if (error) reject(error);
                    else resolve({publicKey, privateKey});
                });
            });
            if (!this.running || this.session !== session) return null;
            // ponytail: session-only demo keys; add protected storage with the messaging protocol.
            this.keys = {scheme, ...keys};
            return this.keys;
        }
        finally {
            if (this.session === session) this.generating = false;
        }
    }

    getSettingsPanel() {
        const plugin = this;
        const {createElement: h, useState} = BdApi.React;
        const canGenerate = typeof Crypto?.generateKeyPair === "function";
        return h(function Panel() {
            const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
            const [decoding, setDecoding] = useState(plugin.decodeIncoming !== false);
            const [scheme, setScheme] = useState(plugin.scheme || "ml-kem-768");
            const [publicKey, setPublicKey] = useState(() => plugin.keys && plugin.keys.scheme === plugin.scheme
                ? plugin.keys.publicKey.export({type: "spki", format: "pem"}) : "");
            const [busy, setBusy] = useState(false);
            const [status, setStatus] = useState("");
            return h("div", {className: "qcord-panel"},
                h("label", null, h("input", {
                    type: "checkbox", checked: enabled, disabled: !plugin.running,
                    onChange: event => { plugin.setEnabled(event.target.checked); setEnabled(plugin.enabled); }
                }), "Encode outgoing messages"),
                h("label", null, h("input", {
                    type: "checkbox", checked: decoding, disabled: !plugin.running,
                    onChange: event => { plugin.setDecoding(event.target.checked); setDecoding(plugin.decodeIncoming); }
                }), "Decoding incoming messages"),
                h("p", null, "Base64 is not encryption."),
                h("label", {className: "qcord-field"}, "PQC key demo", h("select", {
                    value: scheme, disabled: busy || !plugin.running,
                    onChange: event => {
                        plugin.scheme = event.target.value;
                        BdApi.Data.save(NAME, "scheme", plugin.scheme);
                        setScheme(plugin.scheme); setStatus("");
                        setPublicKey(plugin.keys?.scheme === plugin.scheme
                            ? plugin.keys.publicKey.export({type: "spki", format: "pem"}) : "");
                    }
                }, ...SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase())))),
                h("p", null, scheme.startsWith("ml-kem") ? "Key agreement" : "Digital signatures"),
                h("button", {
                    type: "button", disabled: busy || !plugin.running || !canGenerate,
                    onClick: async () => {
                        setBusy(true); setStatus("Generating…");
                        try {
                            const generated = await plugin.generateKeys(scheme);
                            if (generated) {
                                setPublicKey(generated.publicKey.export({type: "spki", format: "pem"}));
                                setStatus("Demo keys generated locally.");
                            }
                            else setStatus("Qcord stopped; generated keys discarded.");
                        }
                        catch (error) { setStatus(`Key generation failed: ${error.message}`); }
                        finally { setBusy(false); }
                    }
                }, busy ? "Generating…" : "Generate keys"),
                h("div", {role: "status"}, status),
                publicKey && h("label", {className: "qcord-field"}, "Public key", h("textarea", {readOnly: true, rows: 4, value: publicKey})),
                h("p", null, `${plugin.running ? "Qcord running" : "Qcord stopped"} · Crypto ${Crypto ? "loaded" : "unavailable"} · Key API ${canGenerate ? "available" : "unavailable"}`),
                h("p", null, "Demo keys are session-only; messages are not encrypted.")
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
        this.session = null;
        if (this.frame !== null && this.frame !== undefined) cancelAnimationFrame(this.frame);
        this.frame = null;
        BdApi.Patcher.unpatchAll(NAME);
        BdApi.DOM.removeStyle(NAME);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) button.remove();
        this.clearDecoded(); //test
    }
};
