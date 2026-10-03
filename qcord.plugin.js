/**
 * @name Qcord
 * @author Eric, Arsh, Yasukha
 * @authorId 215269534540496896
 * @version 0.3.1
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
<svg width="24" height="24" viewBox="0 0 56 56" xmlns="http://www.w3.org/2000/svg" fill="currentColor" aria-hidden="true" focusable="false"><path d="M 27.9883 51.2969 C 28.3633 51.2969 28.9492 51.1562 29.5586 50.8516 C 42.6602 43.4688 47.1836 40.3750 47.1836 31.9609 L 47.1836 14.2891 C 47.1836 11.8750 46.1289 11.1016 44.1836 10.2813 C 41.4414 9.1562 32.6524 5.9922 29.9336 5.0313 C 29.3008 4.8438 28.6680 4.7031 27.9883 4.7031 C 27.3320 4.7031 26.6992 4.8438 26.0664 5.0313 C 23.3476 6.0156 14.5586 9.1797 11.8164 10.2813 C 9.8711 11.0781 8.8164 11.8750 8.8164 14.2891 L 8.8164 31.9609 C 8.8164 40.3750 13.3633 43.4453 26.4414 50.8516 C 27.0508 51.1562 27.6133 51.2969 27.9883 51.2969 Z M 19.7617 35.7344 L 19.7617 26.6406 C 19.7617 25.1172 20.3476 24.3203 21.5898 24.1328 L 21.5898 21.3203 C 21.5898 17.0078 24.1914 14.1016 27.9883 14.1016 C 31.8086 14.1016 34.3867 17.0078 34.3867 21.3203 L 34.3867 24.1094 C 35.6524 24.2969 36.2383 25.0938 36.2383 26.6406 L 36.2383 35.7344 C 36.2383 37.4922 35.4649 38.3125 33.8242 38.3125 L 22.1524 38.3125 C 20.5351 38.3125 19.7617 37.4922 19.7617 35.7344 Z M 24.0508 24.0860 L 31.9492 24.0625 L 31.9492 21.0625 C 31.9492 18.2969 30.3789 16.4687 27.9883 16.4687 C 25.6211 16.4687 24.0508 18.2969 24.0508 21.0625 Z"/></svg>
`;

// protocol:version:scheme:payload
const PREFIX = "qcord:v1:b64:";
// Standard Base64: groups of 4 chars, optional "=" / "==" padding on the last group only.
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const MAX_CONTENT_LENGTH = 2000; // Conservative limit, including non-Nitro accounts.
const MESSAGE_SELECTOR = '[id^="message-content-"]';
const BUTTON_SELECTOR = ".qcord-button";
const DECODED_SELECTOR = ".qcord-plain";
const BUTTON_CSS = `
    .qcord-button {
        --qcord-icon-off: #c5c6ca;
        --qcord-icon-on: #ffffff;
        --qcord-accent: #63862b;
        display: inline-flex; align-items: center; justify-content: center;
        align-self: center; flex-shrink: 0; margin: 0;
        width: 32px; height: 32px; padding: 4px 4px; box-sizing: border-box;
        border: 0; border-radius: 25%; cursor: pointer;
        background: transparent; color: var(--qcord-icon-off);
    }
    .qcord-button:focus-visible { outline: 2px solid var(--text-link); }
    .qcord-button[data-enabled="true"], .qcord-button:hover {
        color: var(--qcord-icon-on);
        background: linear-gradient(to top, var(--qcord-accent), transparent);
    }
    .qcord-button svg {
        display: block; flex-shrink: 0; width: 24px; height: 24px;
        fill: currentColor; pointer-events: none;
        transition: transform 120ms ease;
    }
    .qcord-button:hover svg { transform: scale(1.075); }
    @media (prefers-reduced-motion: reduce) {
        .qcord-button svg { transition: none; }
    }
    .qcord-decoded > :not(.qcord-plain) { display: none !important; }
    .qcord-plain { white-space: pre-wrap; }
    .qcord-panel { display: grid; gap: 12px; }
    .qcord-panel label { display: flex; align-items: center; gap: 8px; }
    .qcord-panel .qcord-field { display: grid; gap: 6px; }
    .qcord-panel input[type="checkbox"] { accent-color: #63862b; }
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

            let outgoing;
            try {
                const message = args[1];
                if (!message || typeof message.content !== "string") {
                    return this.blockSend("Qcord blocked sending: unrecognized message format.");
                }
                const content = this.encodeText(message.content);
                if (content.length > MAX_CONTENT_LENGTH) {
                    return this.blockSend("Qcord message exceeds 2,000 characters once encoded. Shorten it and try again.");
                }
                // Clone rather than mutate Discord's draft or a caller's message.
                outgoing = args.slice();
                outgoing[1] = {...message, content};
            }
            catch {
                // Never fall back to sending plaintext if conversion fails.
                return this.blockSend("Qcord blocked sending because encoding failed.");
            }
            return original.apply(context, outgoing);
        });

        if (typeof unpatch !== "function") {
            BdApi.UI.showToast("Qcord could not install its send hook. Encoding is unavailable.", {type: "error"});
            return;
        }
        this.running = true;
        BdApi.DOM.addStyle(NAME, BUTTON_CSS);
        this.mountButtons();
        this.scanMessages();
        BdApi.UI.showToast("Qcord ready — open the shield for settings.", {type: "success"});
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
        this.scanMessages();
    }

    clearDecoded() {
        for (const span of document.querySelectorAll(DECODED_SELECTOR)) span.remove();
        for (const element of document.querySelectorAll(".qcord-decoded")) element.classList.remove("qcord-decoded");
    }

    updateButton(button) {
        const checked = String(this.enabled);
        if (button.getAttribute("data-enabled") === checked) return;
        button.setAttribute("data-enabled", checked);
        button.title = `Qcord settings — Base64 encoding ${this.enabled ? "on" : "off"}`;
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
    // nodes are hidden, never edited; the decoded text goes in our own span via
    // textContent (no HTML injection).
    scanMessages() {
        if (!this.running) return;
        if (!this.decodeIncoming) { this.clearDecoded(); return; }
        for (const element of document.querySelectorAll(MESSAGE_SELECTOR)) {
            let span = element.querySelector(`:scope > ${DECODED_SELECTOR}`);
            const source = Array.from(element.childNodes)
                .filter(node => node !== span)
                .map(node => node.textContent)
                .join("");
            const decoded = this.decodeText(source);
            if (decoded === null) {
                if (span) {
                    span.remove();
                    element.classList.remove("qcord-decoded");
                }
                continue;
            }
            if (span && span.textContent === decoded) continue;
            if (!span) {
                span = document.createElement("span");
                span.className = "qcord-plain";
                span.title = "Decoded from Qcord Base64 (encoded, not encrypted)";
                element.append(span);
            }
            span.textContent = decoded;
            element.classList.add("qcord-decoded");
        }
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
        this.clearDecoded();
    }
};
