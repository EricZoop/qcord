"use strict";

const MessageCrypto = require("./messaging");
const config = require("./config");
const getSettingsPanel = require("./settings");
const BUTTON_SVG = require("./button.svg");
const PLUGIN_CSS = require("./styles.css");
const {parameters} = require("./parameters");
const { NAME, ACTIVE_SCHEME, BUTTON_SELECTOR, DECODED_SELECTOR, FILE_NAME_RE, MAX_DECODED_FILE_SIZE } = require("./constants");

module.exports = class Qcord extends MessageCrypto {
    start() {
        config.initialize();
        this.enabled = config.load("quantum_conversations") === true;
        this.pendingSends = new Map();
        this.panels = new Set();
        this.dialogs = new Set();
        this.conversationEpoch = {};
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
        this.scheme = config.load("parameter_set") || ACTIVE_SCHEME;
        parameters(this.scheme);

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
        BdApi.UI.showToast("Qcord ready - open the shield to compose or learn.", {type: "success"});
    }

    blockSend(reason) {
        BdApi.UI.showToast(reason, {type: "error"});
        // Discord's normal send result instructs the composer whether to clear
        // the draft. Resolve without calling the original send function.
        return Promise.resolve({shouldClear: false, shouldRefocus: true});
    }

    async prepareMessageFile(channelId, text) {
        if (this.pendingSends.has(channelId)) return this.blockSend("Qcord is already preparing this attachment.");
        const session = this.session, epoch = this.conversationEpoch;
        this.pendingSends.set(channelId, true);
        try {
            const content = await this.encryptMessage(channelId, text);
            if (!this.running || !this.enabled || this.session !== session || this.conversationEpoch !== epoch) throw new Error("Qcord encryption was stopped.");
            return await this.stageMessageFile(channelId, content);
        }
        catch (error) {
            return this.blockSend(`Qcord did not send your message: ${error.message}`);
        } finally { this.pendingSends.delete(channelId); }
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
            const file = new File([content], filename, {type: "application/json"});
            // Stage the encoded envelope for review; never send the plaintext draft.
            await attachments.addFiles({
                channelId, draftType: 0, showLargeMessageDialog: false,
                files: [{file, platform: 1, isThumbnail: false}]
            });
            BdApi.UI.showToast("Qcord attached your encrypted message. Press Send.", {type: "success"});
            return {shouldClear: true, shouldRefocus: true};
        }
        catch {
            return this.blockSend("Qcord could not prepare the message attachment. Your message was not sent.");
        }
    }

    setEnabled(enabled) {
        if (!this.running || this.resetting) return;
        config.save("quantum_conversations", Boolean(enabled));
        this.enabled = Boolean(enabled);
        this.conversationEpoch = {};
        this.clearDecoded();
        this.fileDecodes = new WeakMap();
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) this.updateButton(button);
        this.scanMessages();
    }

    setScheme(scheme) {
        parameters(scheme);
        if (!this.running) throw new Error("Enable Qcord first.");
        config.save("parameter_set", scheme);
        this.scheme = scheme;
        this.conversationEpoch = {};
    }

    currentChannel() { return BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId(); }

    composerText(channelId = this.currentChannel()) {
        const saved = BdApi.Webpack.getStore?.("DraftStore")?.getDraft?.(channelId, 0);
        const editor = channelId === this.currentChannel() ? document.querySelector('[class*="channelTextArea"] [role="textbox"][contenteditable="true"]') : null;
        return (typeof saved === "string" && saved) || editor?.innerText?.replace(/\n$/, "") || "";
    }

    async stageLearningDraft(draft) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (this.currentChannel() !== draft.channelId) throw new Error("Open the selected recipient's DM before attaching.");
        const partner = this.getDirectPartner(draft.channelId);
        const rows = this.getRecipients(draft.channelId, draft.scheme || ACTIVE_SCHEME);
        const {PQC} = require("./pqc");
        if (rows.length !== 1 || rows[0].user_id !== partner.userId || this.keyId(PQC.createPublicKey(rows[0].public_key_spki_base64)) !== draft.partnerId)
            throw new Error("The recipient key changed. Go back and prepare a new preview.");
        if (this.composerText(draft.channelId).trim()) throw new Error("Clear the Discord composer before attaching. Your message is kept in this walkthrough.");
        const result = await this.stageMessageFile(draft.channelId, draft.wire);
        if (!result.shouldClear) throw new Error("Attachment staging failed. Your preview is still here.");
        return result;
    }

    clearDecoded() {
        for (const span of this.renderedMessages.keys()) this.removeDecoded(span);
        for (const span of document.querySelectorAll(DECODED_SELECTOR)) this.removeDecoded(span);
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
        button.setAttribute("data-enabled", String(this.enabled));
        button.title = `Qcord - Quantum conversations ${this.enabled ? "on" : "off"} - Open walkthrough`;
        button.setAttribute("aria-label", button.title);
    }

    mountButtons() {
        if (!this.running || this.resetting) return;
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
                    this.openComposer();
                });
            }
            this.updateButton(button);
            if (controls.firstElementChild !== button) controls.prepend(button);
        }
    }

    // Decrypt visible .qcord attachments.
    // Idempotent: safe to run on every DOM mutation. The original React-owned
    // nodes are hidden, never edited; Discord's Markdown renderer owns our nodes.
    scanMessages() {
        if (!this.running || this.resetting) return;
        if (!this.enabled) { this.clearDecoded(); return; }
        for (const element of this.renderedMessages.keys()) {
            if (!element.isConnected) this.removeDecoded(element);
        }
        for (const link of document.querySelectorAll('[id^="chat-messages-"] a[href]')) {
            this.decodeFile(link);
        }
    }

    async decodeFile(link) {
        if (!this.running || !this.enabled) return;
        let url;
        try { url = new URL(link.href); }
        catch { return; }
        if (url.protocol !== "https:" || url.port || url.username || url.password ||
            !["cdn.discordapp.com", "media.discordapp.net"].includes(url.hostname) ||
            !/^\/attachments\/\d+\/\d+\//.test(url.pathname)) return;
        if (!FILE_NAME_RE.test(url.pathname.split("/").pop())) return;
        // Hide the outer attachment item so its preview leaves no blank tile.
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
                // Bound parsing; BdApi.Net currently buffers the response before this check.
                if (Number(response.headers.get("content-length")) > MAX_DECODED_FILE_SIZE) return;
                const text = await response.text();
                if (text.length > MAX_DECODED_FILE_SIZE || this.session !== session) return;
                const channelId = link.closest('[id^="chat-messages-"]')?.id?.match(/^chat-messages-(\d+)-\d+$/)?.[1];
                state.decoded = await this.decryptMessage(text, channelId);
                if (this.session !== session) return;
            }
            catch (error) {
                // Keep the original attachment available if download/decoding fails.
                BdApi.Logger.warn(NAME, "Could not decode a Qcord attachment.", error);
            }
            finally { state.pending = false; }
        }
        if (state.pending || state.decoded === null || !this.running || !this.enabled ||
            !card.isConnected || link.href !== state.url || this.fileDecodes.get(card) !== state) return;
        if (!state.span?.isConnected) {
            state.span = document.createElement("div");
            state.span.className = `qcord-plain qcord-file-plain ${this.markupClass}`;
            state.span.title = "Decrypted locally by Qcord (ML-KEM + AES-256-GCM)";
            card.after(state.span);
            this.renderDecoded(state.span, state.decoded);
        }
        card.classList.add("qcord-file-hidden");
    }

    getSettingsPanel() { return getSettingsPanel(this); }

    openComposer() {
        if (this.composerDialog?.open) { this.composerDialog.focus(); return; }
        const dialog = document.createElement("dialog");
        dialog.className = "qcord-dialog";
        dialog.setAttribute("aria-label", "Qcord message composer");
        document.body.append(dialog);
        const root = BdApi.ReactDOM.createRoot(dialog);
        const close = () => dialog.close();
        this.dialogs.add(close);
        this.composerDialog = dialog;
        dialog.addEventListener("close", () => {
            root.unmount(); dialog.remove(); this.dialogs.delete(close);
            if (this.composerDialog === dialog) this.composerDialog = null;
        }, {once: true});
        root.render(getSettingsPanel(this, {onClose: close}));
        dialog.showModal();
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
        this.resetting = false;
        for (const close of this.dialogs || []) close();
        for (const close of this.panels || []) close();
        this.panels?.clear();
        this.keys = null;
        this.keyPairs.clear();
        this.keyTasks.clear();
        this.session = null;
        if (this.frame !== null && this.frame !== undefined) cancelAnimationFrame(this.frame);
        this.frame = null;
        BdApi.Patcher.unpatchAll(NAME);
        BdApi.DOM.removeStyle(NAME);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) button.remove();
        this.clearDecoded();
    }
};
