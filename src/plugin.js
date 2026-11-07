"use strict";

const Encapsulation = require("./messaging");
const config = require("./config");
const getSettingsPanel = require("./settings");
const BUTTON_SVG = require("./button.svg");
const PLUGIN_CSS = require("./styles.css");
const AttachmentDecoder = require("./attachments");
const {parameters} = require("./parameters");
const {NAME, ACTIVE_SCHEME, BUTTON_SELECTOR} = require("./constants");

module.exports = class Qcord extends Encapsulation {
    start() {
        config.initialize();
        this.panels = new Set();
        this.dialogs = new Set();
        this.resets = new Set();
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
        BdApi.DOM.addStyle(NAME, PLUGIN_CSS);
        this.mountButtons();
        this.attachments.scan();
        BdApi.UI.showToast("Qcord ready — inspect a recipient key to begin.", {type: "success"});
    }

    currentChannel() { return BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId(); }

    messageContent(text, channelId) {
        try {
            if (this.markdown) return this.markdown.parse(text, true, {allowLinks: true, channelId});
        } catch (error) { BdApi.Logger.warn(NAME, "Discord Markdown rendering failed; displaying plain text.", error); }
        // React renders this string as text, never HTML.
        return text;
    }

    async stageDraft(draft) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (this.currentChannel() !== draft.channelId) throw new Error("Open the selected recipient's DM before attaching.");
        const attachments = BdApi.Webpack.getByKeys("addFiles");
        if (typeof attachments?.addFiles !== "function") throw new Error("Qcord could not find Discord's attachment staging.");
        const session = this.session;
        await this.saveDraft(draft);
        this.checkSession(session);
        if (this.currentChannel() !== draft.channelId) throw new Error("Open the selected recipient's DM before attaching.");
        const file = new File([draft.wire], `${Date.now()}.qcord`, {type: "application/json"});
        await attachments.addFiles({channelId: draft.channelId, draftType: 0, showLargeMessageDialog: false,
            files: [{file, platform: 1, isThumbnail: false}]});
        BdApi.UI.showToast("Qcord attached the encapsulation. Review it and press Send.", {type: "success"});
    }

    mountButtons() {
        if (!this.running) return;
        for (const editor of document.querySelectorAll('[role="textbox"][contenteditable="true"]')) {
            const composer = editor.closest('[class*="channelTextArea"]');
            const controls = composer?.querySelector('[class*="buttons_"]');
            if (!controls) continue;
            let button = composer.querySelector(BUTTON_SELECTOR);
            if (!button) {
                button = document.createElement("button");
                button.type = "button";
                button.className = "qcord-button";
                button.title = "Qcord — ML-KEM encapsulation";
                button.setAttribute("aria-label", button.title);
                button.setAttribute("aria-haspopup", "dialog");
                button.innerHTML = BUTTON_SVG;
                button.addEventListener("mousedown", event => event.preventDefault());
                button.addEventListener("click", event => { event.preventDefault(); event.stopPropagation(); this.openComposer(); });
            }
            if (controls.firstElementChild !== button) controls.prepend(button);
        }
    }

    getSettingsPanel() { return getSettingsPanel(this); }

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
        dialog.addEventListener("close", () => {
            root.unmount(); dialog.remove(); this.dialogs.delete(close);
            if (this.composerDialog === dialog) this.composerDialog = null;
        }, {once: true});
        root.render(getSettingsPanel(this, {onClose: close}));
        dialog.showModal();
    }

    observer() { this.scheduleMount(); }
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
        for (const pair of this.keyPairs?.values() || []) pair.privateKey.bytes.fill(0);
        this.keyPairs?.clear();
        this.keyTasks?.clear();
        if (this.frame !== null && this.frame !== undefined) cancelAnimationFrame(this.frame);
        this.frame = null;
        BdApi.DOM.removeStyle(NAME);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) button.remove();
    }
};
