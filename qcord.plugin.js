/**
 * @name Qcord
 * @author EricZoop
 * @authorId 215269534540496896
 * @version 0.1.0
 * @description Client-side Wingdings-style message encoding proof of concept. Not encryption.
 * @invite GSdMfMBW5g
 * @source https://github.com/EricZoop/qcord
 */

"use strict";

const NAME = "Qcord";
// A portable Unicode dingbat alphabet, not a font applied to plaintext.
// Encode each UTF-8 byte as two symbols so every character is covered.
const SYMBOLS = Array.from("✀✁✂✃✄☎☏✆✉✍✎✏✐✑✒✓");
const MAX_CONTENT_LENGTH = 2000; // Conservative limit, including non-Nitro accounts.
const TOGGLE_SELECTOR = ".qcord-toggle";

module.exports = class Qcord {
    start() {
        this.enabled = BdApi.Data.load(NAME, "enabled") === true;
        this.running = false;
        this.frame = null;

        // Discord internals are not a stable API. Do not present a working switch
        // unless we can actually intercept ordinary chat submissions.
        const actions = BdApi.Webpack.getByKeys("sendMessage", "editMessage");
        if (!actions || typeof actions.sendMessage !== "function") {
            BdApi.UI.showToast("Qcord could not find Discord's send function. The effect is unavailable.", {type: "error"});
            return;
        }

        const unpatch = BdApi.Patcher.instead(NAME, actions, "sendMessage", (context, args, original) => {
            if (!this.enabled) return original.apply(context, args);

            let outgoing;
            try {
                const message = args[1];
                if (!message || typeof message.content !== "string") {
                    return this.blockSend("Qcord blocked sending: unrecognized message format.");
                }
                const content = this.encodeText(message.content);
                if (content.length > MAX_CONTENT_LENGTH) {
                    return this.blockSend("Qcord symbols exceed 2,000 characters. Shorten your message and try again.");
                }
                // Clone rather than mutate Discord's draft or a caller's message.
                outgoing = args.slice();
                outgoing[1] = {...message, content};
            }
            catch {
                // Never fall back to sending plaintext if conversion fails.
                return this.blockSend("Qcord blocked sending because text conversion failed.");
            }
            return original.apply(context, outgoing);
        });

        if (typeof unpatch !== "function") {
            BdApi.UI.showToast("Qcord could not install its send hook. The effect is unavailable.", {type: "error"});
            return;
        }
        this.running = true;
        BdApi.DOM.addStyle(NAME, `
            .qcord-toggle {
                display: inline-flex; align-items: center; gap: 5px;
                align-self: center; flex-shrink: 0; margin: 0 8px 0 0;
                padding: 5px; border: 0; border-radius: 5px; cursor: pointer;
                background: transparent; color: var(--text-muted); font-size: 12px;
            }
            .qcord-toggle:hover { background: var(--background-modifier-hover); }
            .qcord-toggle:focus-visible { outline: 2px solid var(--text-link); }
            .qcord-toggle[aria-checked="true"] { color: var(--text-normal); }
            .qcord-track { width: 26px; height: 16px; border-radius: 8px;
                background: var(--text-muted); position: relative; }
            .qcord-toggle[aria-checked="true"] .qcord-track { background: #248046; }
            .qcord-thumb { position: absolute; top: 2px; left: 2px;
                width: 12px; height: 12px; border-radius: 50%; background: white; }
            .qcord-toggle[aria-checked="true"] .qcord-thumb { left: 12px; }
        `);
        this.mountToggles();
    }

    encodeText(text) {
        let result = "";
        for (const byte of new TextEncoder().encode(text)) {
            result += SYMBOLS[byte >> 4] + SYMBOLS[byte & 15];
        }
        return result;
    }

    blockSend(reason) {
        BdApi.UI.showToast(reason, {type: "error"});
        // Discord's normal send result instructs the composer whether to clear
        // the draft. Resolve without calling the original send function.
        return Promise.resolve({shouldClear: false, shouldRefocus: true});
    }

    setEnabled(enabled) {
        BdApi.Data.save(NAME, "enabled", Boolean(enabled));
        this.enabled = Boolean(enabled);
        for (const button of document.querySelectorAll(TOGGLE_SELECTOR)) this.updateToggle(button);
    }

    updateToggle(button) {
        const checked = String(this.enabled);
        if (button.getAttribute("aria-checked") === checked) return;
        button.setAttribute("aria-checked", checked);
        button.title = `Qcord Wingdings-style effect: ${this.enabled ? "ON" : "OFF"}. Click to toggle. Not encryption.`;
        button.setAttribute("aria-label", `Wingdings-style text effect ${this.enabled ? "on" : "off"}`);
    }

    mountToggles() {
        if (!this.running) return;
        // Scope to message composers, excluding unrelated attachment controls.
        // Class fragments avoid depending on Discord's changing CSS hashes.
        for (const editor of document.querySelectorAll('[role="textbox"][contenteditable="true"]')) {
            const composer = editor.closest('[class*="channelTextArea"]');
            if (!composer) continue;
            const attach = composer.querySelector('button[class*="attachButton"], [role="button"][class*="attachButton"]');
            if (!attach) continue;
            const anchor = attach.closest('[class*="attachWrapper"]') || attach;
            let button = composer.querySelector(TOGGLE_SELECTOR);
            if (!button) {
                button = document.createElement("button");
                button.type = "button";
                button.className = "qcord-toggle";
                button.setAttribute("role", "switch");
                const label = document.createElement("span");
                label.textContent = "WD";
                const track = document.createElement("span");
                track.className = "qcord-track";
                track.setAttribute("aria-hidden", "true");
                const thumb = document.createElement("span");
                thumb.className = "qcord-thumb";
                track.append(thumb);
                button.append(label, track);
                button.addEventListener("mousedown", event => event.preventDefault());
                button.addEventListener("click", event => {
                    event.preventDefault();
                    event.stopPropagation();
                    this.setEnabled(!this.enabled);
                });
            }
            this.updateToggle(button);
            if (anchor.nextElementSibling !== button) anchor.after(button);
        }
    }

    // BetterDiscord's lifecycle supplies DOM mutations and navigation events.
    observer() { this.scheduleMount(); }
    onSwitch() { this.scheduleMount(); }

    scheduleMount() {
        if (!this.running || this.frame !== null) return;
        this.frame = requestAnimationFrame(() => {
            this.frame = null;
            this.mountToggles();
        });
    }

    stop() {
        this.running = false;
        if (this.frame !== null && this.frame !== undefined) cancelAnimationFrame(this.frame);
        this.frame = null;
        BdApi.Patcher.unpatchAll(NAME);
        BdApi.DOM.removeStyle(NAME);
        for (const button of document.querySelectorAll(TOGGLE_SELECTOR)) button.remove();
    }
};
