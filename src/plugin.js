"use strict";

const MessageCrypto = require("./messaging");
const getSettingsPanel = require("./settings");
const BUTTON_SVG = require("./button.svg");
const PLUGIN_CSS = require("./styles.css");
const { NAME, KEY_STORE, KEM_SCHEMES, PREFIX, ENCRYPTED_PREFIX, BASE64_RE, MESSAGE_SELECTOR, BUTTON_SELECTOR, DECODED_SELECTOR, FILE_NAME_RE, MAX_DECODED_FILE_SIZE } = require("./constants");

module.exports = class Qcord extends MessageCrypto {
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

    getSettingsPanel() { return getSettingsPanel(this); }

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
