"use strict";

const Encapsulation = require("./messaging");
const config = require("./config");
const getSettingsPanel = require("./settings");
const BUTTON_SVG = require("./button.svg");
const PLUGIN_CSS = `@font-face { font-family: "Qcord Inter"; src: url("${require("./fonts/InterVariable.woff2")}") format("woff2"); font-style: normal; font-weight: 100 900; font-display: swap; }\n` + require("./styles.css");
const AttachmentDecoder = require("./attachments");
const dismissOnBackdrop = require("./dialog");
const {parameters} = require("./parameters");
const {NAME, ACTIVE_SCHEME, BUTTON_SELECTOR} = require("./constants");

module.exports = class Qcord extends Encapsulation {
    start() {
        config.initialize();
        this.panels = new Set();
        this.dialogs = new Set();
        this.resets = new Set();
        this.modeListeners = new Set();
        this.pendingSends = new Map();
        this.outgoingEpoch = {};
        this.autoEncrypt = config.load("auto_encrypt") === true;
        this.autoDecrypt = config.load("auto_decrypt") !== false;
        this.keyPairs = new Map();
        this.keyTasks = new Map();
        this.session = {};
        this.frame = null;
        this.scheme = ACTIVE_SCHEME;
        parameters(this.scheme);
        this.markdown = BdApi.Webpack.getByKeys("parse", "reactParserFor");
        this.markupClass = BdApi.Webpack.getByKeys("markup")?.markup || "";
        this.attachments = new AttachmentDecoder(this);
        this.running = true;
        this.installSendHook();
        BdApi.DOM.addStyle(NAME, PLUGIN_CSS);
        this.mountButtons();
        this.attachments.scan();
        BdApi.UI.showToast("Qcord ready. Inspect a recipient key to begin.", {type: "success"});
    }

    currentChannel() { return BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId(); }

    installSendHook() {
        const actions = BdApi.Webpack.getByKeys("sendMessage", "editMessage");
        this.sendHookReady = false;
        try { if (typeof actions?.sendMessage === "function" && BdApi.Patcher?.instead) {
            const unpatch = BdApi.Patcher.instead(NAME, actions, "sendMessage", (context, args, original) => {
                if (!this.running || !this.autoEncrypt) return original.apply(context, args);
                if (typeof args[1]?.content !== "string") return this.blockSend("Qcord could not recognize this message. Your draft was kept.");
                if (args[1].content.length) return this.prepareAutomaticMessage(args[0], args[1].content);
                return original.apply(context, args); // Send the reviewed .qcord attachment.
            });
            this.sendHookReady = typeof unpatch === "function";
        } } catch (error) { BdApi.Logger.warn(NAME, "Could not install Qcord's automatic encryption hook.", error); }
        if (!this.sendHookReady && this.autoEncrypt) {
            this.autoEncrypt = false; config.save("auto_encrypt", false);
            BdApi.UI.showToast("Qcord could not install automatic encryption. Auto-encrypt is off.", {type: "error"});
        }
    }

    blockSend(reason) {
        BdApi.UI.showToast(reason, {type: "error"});
        return Promise.resolve({shouldClear: false, shouldRefocus: true});
    }

    setAutomatic(mode, enabled) {
        if (!this.running || this.resetting) throw new Error("Wait until Qcord is ready.");
        if (!["encrypt", "decrypt"].includes(mode)) throw new Error("Unknown automatic mode.");
        if (mode === "encrypt" && enabled && !this.sendHookReady) throw new Error("Automatic encryption is unavailable in this Discord build.");
        config.save(`auto_${mode}`, Boolean(enabled));
        if (mode === "encrypt") { this.autoEncrypt = Boolean(enabled); this.outgoingEpoch = {}; }
        else { this.autoDecrypt = Boolean(enabled); this.attachments.clear(); }
        this.mountButtons(); this.attachments.scan();
        for (const notify of this.modeListeners) notify();
    }

    async prepareAutomaticMessage(channelId, text) {
        if (this.pendingSends.has(channelId)) return this.blockSend("Qcord is already preparing this attachment.");
        const session = this.session, epoch = this.outgoingEpoch;
        this.pendingSends.set(channelId, true);
        let draft;
        try {
            draft = await this.prepareEncapsulation(channelId, ACTIVE_SCHEME, text);
            if (!this.running || !this.autoEncrypt || this.session !== session || this.outgoingEpoch !== epoch) throw new Error("Automatic encryption was cancelled. Your draft was kept.");
            await this.stageDraft(draft, () => this.autoEncrypt && this.outgoingEpoch === epoch);
            return {shouldClear: true, shouldRefocus: true};
        } catch (error) { return this.blockSend(error.message); }
        finally { require("./mlkem").wipe(draft); this.pendingSends.delete(channelId); }
    }

    messageContent(text, channelId) {
        try {
            if (this.markdown) return this.markdown.parse(text, true, {allowLinks: true, channelId});
        } catch (error) { BdApi.Logger.warn(NAME, "Discord Markdown rendering failed; displaying plain text.", error); }
        // React renders this string as text, never HTML.
        return text;
    }

    async stageDraft(draft, stillAllowed = () => true) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (this.currentChannel() !== draft.channelId) throw new Error("Open the selected recipient's DM before attaching.");
        const attachments = BdApi.Webpack.getByKeys("addFiles");
        if (typeof attachments?.addFiles !== "function") throw new Error("Qcord could not find Discord's attachment staging.");
        const session = this.session;
        await this.saveDraft(draft);
        this.checkSession(session);
        if (!stillAllowed()) throw new Error("Automatic encryption was cancelled. Your draft was kept.");
        if (this.currentChannel() !== draft.channelId) throw new Error("Open the selected recipient's DM before attaching.");
        const file = new File([draft.wire], `${Date.now()}.qcord`, {type: "application/json"});
        await attachments.addFiles({channelId: draft.channelId, draftType: 0, showLargeMessageDialog: false,
            files: [{file, platform: 1, isThumbnail: false}]});
        BdApi.UI.showToast("Encrypted attachment ready. Press Send to share it.", {type: "success"});
    }

    mountButtons() {
        if (!this.running) return;
        for (const editor of document.querySelectorAll('[role="textbox"][contenteditable="true"]')) {
            const composer = editor.closest('[class*="channelTextArea"]');
            const controls = composer?.querySelector('[class*="buttons_"]');
            if (!controls) continue;
            if (composer.classList.contains("qcord-encrypt-enabled") !== this.autoEncrypt) composer.classList.toggle("qcord-encrypt-enabled", this.autoEncrypt);
            let button = composer.querySelector(BUTTON_SELECTOR);
            if (!button) {
                button = document.createElement("button");
                button.type = "button";
                button.className = "qcord-button";
                button.setAttribute("aria-haspopup", "dialog");
                button.innerHTML = BUTTON_SVG;
                button.addEventListener("mousedown", event => event.preventDefault());
                button.addEventListener("click", event => { event.preventDefault(); event.stopPropagation(); this.openComposer(); });
            }
            if (button.classList.contains("qcord-decrypt-enabled") !== this.autoDecrypt) button.classList.toggle("qcord-decrypt-enabled", this.autoDecrypt);
            const title = `Qcord · Auto-encrypt ${this.autoEncrypt ? "on" : "off"} · Auto-decrypt ${this.autoDecrypt ? "on" : "off"}`;
            if (button.title !== title) button.title = title;
            if (button.getAttribute("aria-label") !== title) button.setAttribute("aria-label", title);
            if (controls.firstElementChild !== button) controls.prepend(button);
        }
    }

    getSettingsPanel() { return getSettingsPanel(this); }

    dismissDialogs() { for (const close of [...this.dialogs].reverse()) close(); }

    openComposer() {
        if (this.composerDialog?.open) { this.composerDialog.focus(); return; }
        const dialog = document.createElement("dialog");
        dialog.className = "qcord-dialog";
        dialog.setAttribute("aria-label", "Qcord encapsulation");
        document.body.append(dialog);
        const root = BdApi.ReactDOM.createRoot(dialog);
        const close = () => dialog.close();
        this.dialogs.add(close);
        this.composerDialog = dialog;
        const unbind = dismissOnBackdrop(dialog, () => this.dismissDialogs());
        dialog.addEventListener("close", () => {
            unbind();
            root.unmount(); dialog.remove(); this.dialogs.delete(close);
            if (this.composerDialog === dialog) this.composerDialog = null;
        }, {once: true});
        root.render(getSettingsPanel(this, {onClose: close}));
        dialog.showModal();
    }

    observer(mutation) {
        const target = mutation?.target?.nodeType === 1 ? mutation.target : mutation?.target?.parentElement;
        if (target?.closest(".qcord-dialog, .qcord-decrypted, .qcord-button")) return;
        this.scheduleMount();
    }
    onSwitch() { this.attachments?.retry(); this.scheduleMount(); }
    scheduleMount() {
        if (!this.running || this.frame !== null) return;
        this.frame = requestAnimationFrame(() => { this.frame = null; this.mountButtons(); this.attachments?.scan(); });
    }

    stop() {
        this.running = false;
        this.session = null;
        this.attachments?.clear();
        for (const close of this.dialogs || []) close();
        for (const close of this.panels || []) close();
        this.panels?.clear();
        this.resets?.clear();
        this.modeListeners?.clear();
        for (const pair of this.keyPairs?.values() || []) pair.privateKey.bytes.fill(0);
        this.keyPairs?.clear();
        this.keyTasks?.clear();
        if (this.frame !== null && this.frame !== undefined) cancelAnimationFrame(this.frame);
        this.frame = null;
        BdApi.DOM.removeStyle(NAME);
        BdApi.Patcher?.unpatchAll(NAME);
        for (const composer of document.querySelectorAll(".qcord-encrypt-enabled")) composer.classList.remove("qcord-encrypt-enabled");
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) button.remove();
    }
};
