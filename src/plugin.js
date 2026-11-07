"use strict";

const Encapsulation = require("./messaging");
const config = require("./config");
const getSettingsPanel = require("./settings");
const BUTTON_SVG = require("./button.svg");
const PLUGIN_CSS = require("./styles.css");
const {parameters} = require("./parameters");
const {NAME, ACTIVE_SCHEME, BUTTON_SELECTOR} = require("./constants");

module.exports = class Qcord extends Encapsulation {
    start() {
        config.initialize();
        this.panels = new Set();
        this.dialogs = new Set();
        this.keyPairs = new Map();
        this.keyTasks = new Map();
        this.session = {};
        this.frame = null;
        this.scheme = config.load("parameter_set") || ACTIVE_SCHEME;
        parameters(this.scheme);
        this.running = true;
        BdApi.DOM.addStyle(NAME, PLUGIN_CSS);
        this.mountButtons();
        BdApi.UI.showToast("Qcord ready — inspect a recipient key to begin.", {type: "success"});
    }

    setScheme(scheme) {
        parameters(scheme);
        if (!this.running) throw new Error("Enable Qcord first.");
        config.save("parameter_set", scheme);
        this.scheme = scheme;
    }

    currentChannel() { return BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId(); }

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
    onSwitch() { this.scheduleMount(); }
    scheduleMount() {
        if (!this.running || this.frame !== null) return;
        this.frame = requestAnimationFrame(() => { this.frame = null; this.mountButtons(); });
    }

    stop() {
        this.running = false;
        this.session = null;
        for (const close of this.dialogs || []) close();
        for (const close of this.panels || []) close();
        this.panels?.clear();
        for (const pair of this.keyPairs?.values() || []) pair.privateKey.bytes.fill(0);
        this.keyPairs?.clear();
        this.keyTasks?.clear();
        if (this.frame !== null && this.frame !== undefined) cancelAnimationFrame(this.frame);
        this.frame = null;
        BdApi.DOM.removeStyle(NAME);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) button.remove();
    }
};
