"use strict";

const {PQC} = require("./pqc");
const {ACTIVE_SCHEME} = require("./constants");

module.exports = function getSettingsPanel(plugin) {
    const {createElement: h, useState, useEffect} = BdApi.React;
    const channelId = BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId();
    return h(function Panel() {
        let partner = null;
        try { partner = plugin.getDirectPartner(channelId); } catch {}
        const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
        const [decoding, setDecoding] = useState(plugin.decodeIncoming !== false);
        const [publicKey, setPublicKey] = useState("");
        const [createdAt, setCreatedAt] = useState(null);
        const [saved, setSaved] = useState(() => plugin.getRecipients(channelId, ACTIVE_SCHEME));
        const [recipientKey, setRecipientKey] = useState("");
        const [busy, setBusy] = useState(true);
        const [status, setStatus] = useState("");
        const current = partner && saved.length === 1 && saved[0].userId === partner.userId ? saved[0] : null;
        const exportPublic = key => key.export({type: "spki", format: "base64"});
        useEffect(() => {
            let active = true;
            plugin.generateKeys(ACTIVE_SCHEME).then(keys => {
                if (active) { setPublicKey(exportPublic(keys.publicKey)); setCreatedAt(keys.createdAt); }
            }).catch(error => { if (active) setStatus(error.message); })
                .finally(() => { if (active) setBusy(false); });
            return () => { active = false; };
        }, []);
        const button = (label, onClick, disabled = false, className = "") => h("button", {
            type: "button", className, disabled: disabled || busy || !plugin.running || plugin.resetting, onClick
        }, label);
        const copy = async text => {
            try { await navigator.clipboard.writeText(text); setStatus("Public key copied."); }
            catch { setStatus("Select and copy the key manually; clipboard access is unavailable."); }
        };
        const copyIcon = () => h("svg", {width: 24, height: 24, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true, focusable: false},
            h("rect", {width: 14, height: 14, x: 8, y: 8, rx: 2, ry: 2}),
            h("path", {d: "M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}));
        const copyButton = (label, text) => button(h("span", {className: "qcord-copy-label"}, copyIcon(), label), () => copy(text));
        const saveKey = () => {
            try {
                plugin.saveRecipients(channelId, [{userId: partner?.userId, publicKey: recipientKey}], ACTIVE_SCHEME);
                setSaved(plugin.getRecipients(channelId, ACTIVE_SCHEME));
                setRecipientKey(""); setStatus("DM partner's key saved.");
            } catch (error) { setStatus(error.message); }
        };
        const removeKey = () => {
            try {
                plugin.saveRecipients(channelId, [], ACTIVE_SCHEME);
                setSaved([]); setStatus("Saved key removed.");
            } catch (error) { setStatus(error.message); }
        };
        const testKey = async () => {
            setBusy(true);
            setStatus("Checking key exchange, encryption and tamper rejection...");
            try { await plugin.testScheme(ACTIVE_SCHEME, "Qcord key check"); setStatus("Passed: key exchange, message encryption/decryption, and tamper rejection. This local test does not need a DM partner."); }
            catch (error) { setStatus(error.message); }
            finally { setBusy(false); }
        };
        const createKey = async () => {
            setBusy(true);
            try {
                const keys = await plugin.generateKeys(ACTIVE_SCHEME);
                setPublicKey(exportPublic(keys.publicKey)); setCreatedAt(keys.createdAt);
                setStatus("New key pair saved. Exchange your new public key with your partner.");
            }
            catch (error) { setStatus(error.message); }
            finally { setBusy(false); }
        };
        const resetConfig = () => BdApi.UI.showConfirmationModal("Clear Qcord configuration?",
            "This deletes your private keys, partner keys and settings. Without a backup, messages encrypted to deleted keys cannot be recovered.", {
                danger: true, confirmText: "Clear configuration", cancelText: "Cancel",
                onConfirm: async () => {
                    setBusy(true);
                    try {
                        await plugin.clearConfiguration();
                        setStatus("Configuration cleared. Create a new key pair to start again.");
                    } catch (error) { setStatus(error.message); }
                    finally {
                        setPublicKey(""); setCreatedAt(null); setSaved([]); setRecipientKey("");
                        setEnabled(false); setDecoding(false); setBusy(false);
                    }
                }
            });
        const toggle = (label, checked, onChange) => h("label", {className: "qcord-toggle"},
            h("input", {type: "checkbox", checked, disabled: !plugin.running || plugin.resetting, onChange}), label);
        const lesson = (title, text) => h("div", null, h("h4", null, title), h("p", null, text));
        return h("div", {className: "qcord-panel"},
            h("div", {className: "qcord-heading"}, h("h3", null, "Direct messaging"), h("span", null, "ML-KEM-512")),
            h("div", {className: "qcord-switches"},
                toggle("Encrypt outgoing", enabled, event => { plugin.setEnabled(event.target.checked); setEnabled(plugin.enabled); }),
                toggle("Decrypt incoming", decoding, event => { plugin.setDecoding(event.target.checked); setDecoding(plugin.decodeIncoming); })),
            h("p", null, "Enter prepares the encrypted file. Press Send or Enter again to send it."),
            h("div", {className: "qcord-workspace"},
                h("section", {className: "qcord-section"},
                    h("h3", null, "My public key", publicKey && h("span", {className: "qcord-created-at"},
                        createdAt && Number.isFinite(Date.parse(createdAt))
                            ? " (created " + new Date(createdAt).toLocaleString() + ")"
                            : " (creation date unavailable)")),
                    h("textarea", {readOnly: true, rows: 4, value: publicKey, placeholder: "Loading key...", "aria-label": "My public key"}),
                    h("div", {className: "qcord-actions"}, publicKey ? copyButton("Copy public key", publicKey) : button("Create key pair", createKey),
                        button("Check my key pair", testKey, !publicKey)),
                    publicKey && h("p", {className: "qcord-fingerprint"}, "SHA-256: " + plugin.keyId(PQC.createPublicKey(publicKey)))),
                h("section", {className: "qcord-section"},
                    h("h3", null, "DM partner"),
                    partner ? h("div", {className: "qcord-identifiers"},
                        h("p", null, "User ID: ", h("code", null, partner.userId)),
                        h("p", null, "Channel ID: ", h("code", null, channelId)))
                        : h("p", null, "Open a one-to-one DM to exchange keys. Group DMs and server channels are not supported for new encrypted messages."),
                    h("label", {className: "qcord-field"}, current ? "Replacement public key" : "Their public key",
                        h("textarea", {rows: 4, value: recipientKey, placeholder: "Paste their ML-KEM-512 public key", disabled: busy || !partner || !plugin.running,
                            onChange: event => setRecipientKey(event.target.value)})),
                    h("div", {className: "qcord-actions"},
                        button(current ? "Replace key" : "Save key", saveKey, !partner || !recipientKey.trim())),
                    current && h("div", {className: "qcord-saved-key"},
                        h("p", {className: "qcord-fingerprint"}, "Saved SHA-256: " + plugin.keyId(PQC.createPublicKey(current.publicKey))),
                        h("div", {className: "qcord-actions"},
                            copyButton("Copy saved key", exportPublic(PQC.createPublicKey(current.publicKey))),
                            button("Remove key", removeKey))),
                    h("p", null, "Compare fingerprints with your partner through a trusted route before sending."))),
            status && h("p", {className: "qcord-status", role: "status", "aria-live": "polite"}, status),
            h("details", {className: "qcord-section"}, h("summary", null, "Keys, IDs and message integrity"),
                h("div", {className: "qcord-lessons"},
                    lesson("User ID vs. channel ID", "A user ID identifies a Discord account even when its @username changes. A channel ID identifies the DM conversation. Qcord reads both from the open DM and saves one partner key for that conversation. You do not need to type either ID. IDs do not prove who owns a public key."),
                    lesson("Public and private keys", "Trade public keys with your partner; keep private keys secret. ML-KEM-512 establishes a shared secret using the public key and matching private key. It is post-quantum cryptography running on ordinary computers, designed to resist future quantum attacks."),
                    lesson("Encryption and integrity", "A fresh AES-256-GCM key encrypts each message. Its authentication tag rejects altered protected content. HKDF-SHA256 derives key-wrapping keys; SHA-256 fingerprints help verify public keys. A plain message hash alone cannot stop someone replacing both the content and its hash."),
                    lesson("One key per contact", "You keep one local key pair and collect a public key from every contact you message: N contacts means N contact keys to manage. Each file includes access for your partner and yourself. There is no shared group key or TreeKEM yet.")),
                h("p", null, "Private keys are stored unencrypted in qcord.config.json. This experimental format has no sender signatures or forward secrecy."),
                h("p", null, "Check your key pair locally, even without a DM partner. This checks cryptography on this device, not Discord delivery.")),
            h("details", {className: "qcord-section"}, h("summary", null, "Future algorithms"),
                h("p", null, "ML-KEM-768/1024: larger standardized parameter sets. HQC: a code-based KEM selected for standardization, planned for evaluation. ML-DSA/SLH-DSA: signatures for sender verification. No release dates yet."),
                h("a", {href: "https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection", target: "_blank", rel: "noreferrer"}, "NIST: HQC selection")),
            h("div", {className: "qcord-actions"}, button("Clear qcord.config.json", resetConfig, false, "qcord-danger"))
        );
    });
};
