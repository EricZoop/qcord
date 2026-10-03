/**
 * @name Qcord
 * @author EricZoop
 * @authorId 215269534540496896
 * @version 0.2.0
 * @description Client-side text effect and post-quantum key-generation demo. Messages are not encrypted.
 * @invite GSdMfMBW5g
 * @source https://github.com/EricZoop/qcord
 */

"use strict";

const NAME = "Qcord";
const {promisify} = require("util");
const generateKeyPair = promisify(require("crypto").generateKeyPair);
const SCHEMES = ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f"];
const BUTTON_SVG = ""; // Replace with the supplied, reviewed SVG. Until then use Q.
// A portable Unicode dingbat alphabet, not a font applied to plaintext.
// Encode each UTF-8 byte as two symbols so every character is covered.
const SYMBOLS = Array.from("✀✁✂✃✄☎☏✆✉✍✎✏✐✑✒✓");
const MAX_CONTENT_LENGTH = 2000; // Conservative limit, including non-Nitro accounts.
const BUTTON_SELECTOR = ".qcord-button";

module.exports = class Qcord {
    start() {
        this.enabled = BdApi.Data.load(NAME, "enabled") === true;
        this.running = false;
        this.frame = null;
        this.session = {};
        this.keys = null;
        this.generating = false;
        const savedScheme = BdApi.Data.load(NAME, "scheme");
        this.scheme = SCHEMES.includes(savedScheme) ? savedScheme : "ml-kem-768";

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
            .qcord-button {
                align-self: center; flex-shrink: 0; margin: 0 8px 0 0;
                width: 32px; height: 32px; padding: 4px; border: 0; border-radius: 5px;
                cursor: pointer; background: transparent; color: var(--text-muted);
            }
            .qcord-button:hover { background: var(--background-modifier-hover); }
            .qcord-button:focus-visible { outline: 2px solid var(--text-link); }
            .qcord-button[data-enabled="true"] { color: var(--text-positive); }
            .qcord-button svg { width: 24px; height: 24px; }
            .qcord-panel { display: grid; gap: 12px; }
            .qcord-panel textarea { width: 100%; box-sizing: border-box; font-family: monospace; }
        `);
        this.mountButtons();
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
        if (!this.running) return;
        BdApi.Data.save(NAME, "enabled", Boolean(enabled));
        this.enabled = Boolean(enabled);
        for (const button of document.querySelectorAll(BUTTON_SELECTOR)) this.updateButton(button);
    }

    updateButton(button) {
        const checked = String(this.enabled);
        if (button.getAttribute("data-enabled") === checked) return;
        button.setAttribute("data-enabled", checked);
        button.title = `Qcord settings — text effect ${this.enabled ? "on" : "off"}`;
        button.setAttribute("aria-label", button.title);
    }

    mountButtons() {
        if (!this.running) return;
        // Scope to message composers, excluding unrelated attachment controls.
        // Class fragments avoid depending on Discord's changing CSS hashes.
        for (const editor of document.querySelectorAll('[role="textbox"][contenteditable="true"]')) {
            const composer = editor.closest('[class*="channelTextArea"]');
            if (!composer) continue;
            const attach = composer.querySelector('button[class*="attachButton"], [role="button"][class*="attachButton"]');
            if (!attach) continue;
            const anchor = attach.closest('[class*="attachWrapper"]') || attach;
            let button = composer.querySelector(BUTTON_SELECTOR);
            if (!button) {
                button = document.createElement("button");
                button.type = "button";
                button.className = "qcord-button";
                button.setAttribute("aria-haspopup", "dialog");
                button.innerHTML = BUTTON_SVG || "Q";
                button.addEventListener("mousedown", event => event.preventDefault());
                button.addEventListener("click", event => {
                    event.preventDefault();
                    event.stopPropagation();
                    BdApi.UI.alert(NAME, this.getSettingsPanel());
                });
            }
            this.updateButton(button);
            if (anchor.nextElementSibling !== button) anchor.after(button);
        }
    }

    async generateKeys(scheme) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (!SCHEMES.includes(scheme)) throw new Error("Unknown key algorithm.");
        if (this.generating) throw new Error("Key generation is already running.");
        const session = this.session;
        this.generating = true;
        try {
            const keys = await generateKeyPair(scheme, {});
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
        return h(function Panel() {
            const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
            const [scheme, setScheme] = useState(plugin.scheme || "ml-kem-768");
            const [publicKey, setPublicKey] = useState(() => plugin.keys && plugin.keys.scheme === plugin.scheme
                ? plugin.keys.publicKey.export({type: "spki", format: "pem"}) : "");
            const [busy, setBusy] = useState(false);
            const [status, setStatus] = useState("");
            return h("div", {className: "qcord-panel"},
                h("label", null, h("input", {
                    type: "checkbox", checked: enabled, disabled: !plugin.running,
                    onChange: event => { plugin.setEnabled(event.target.checked); setEnabled(plugin.enabled); }
                }), " Enable Wingdings-style text effect"),
                h("p", null, "The text effect is not encryption. PQC keys below are a separate demo."),
                h("label", null, "Key demo algorithm ", h("select", {
                    value: scheme, disabled: busy || !plugin.running,
                    onChange: event => {
                        plugin.scheme = event.target.value;
                        BdApi.Data.save(NAME, "scheme", plugin.scheme);
                        setScheme(plugin.scheme); setStatus("");
                        setPublicKey(plugin.keys?.scheme === plugin.scheme
                            ? plugin.keys.publicKey.export({type: "spki", format: "pem"}) : "");
                    }
                }, ...SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase())))),
                h("p", null, scheme.startsWith("ml-kem") ? "Key encapsulation: establishes a shared secret for encryption." : "Digital signatures: authenticates messages; does not encrypt them."),
                h("button", {
                    type: "button", disabled: busy || !plugin.running,
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
                }, busy ? "Generating…" : "Generate / replace demo keys"),
                h("div", {role: "status"}, status),
                h("label", null, "Public key (SPKI PEM)", h("textarea", {readOnly: true, rows: 5, value: publicKey})),
                h("p", null, "Private keys stay in memory and are discarded when Qcord stops. Nothing is sent to Discord. Native PQC requires a compatible Discord Node/OpenSSL runtime (Node 24.8+ supports all listed families).")
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
    }
};
