"use strict";

const {PQC} = require("./pqc");
const {ACTIVE_SCHEME} = require("./constants");

module.exports = function getSettingsPanel(plugin) {
    const {createElement: h, useState, useEffect} = BdApi.React;
    const channelId = BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId();
    return h(function Panel() {
        let openPartner = null;
        try { openPartner = plugin.getDirectPartner(channelId); } catch {}
        const [partners, setPartners] = useState(() => plugin.getSavedPartners());
        const [selectedChannel, setSelectedChannel] = useState(() => openPartner ? channelId : partners[0]?.channel_id || "");
        const selectedSaved = partners.find(row => row.channel_id === selectedChannel);
        let partner = null;
        try { partner = plugin.getDirectPartner(selectedChannel); } catch {}
        const partnerUserId = partner?.userId || selectedSaved?.user_id;
        const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
        const [decoding, setDecoding] = useState(plugin.decodeIncoming !== false);
        const [publicKey, setPublicKey] = useState("");
        const [createdAt, setCreatedAt] = useState(null);
        const [recipientKey, setRecipientKey] = useState("");
        const [busy, setBusy] = useState(true);
        const [status, setStatus] = useState("");
        const current = selectedSaved && (!partner || selectedSaved.user_id === partner.userId) ? selectedSaved : null;
        const exportPublic = key => key.export({type: "spki", format: "base64"});
        useEffect(() => {
            let active = true;
            plugin.generateKeys(ACTIVE_SCHEME).then(keys => {
                if (active) { setPublicKey(exportPublic(keys.publicKey)); setCreatedAt(keys.createdAt); }
            }).catch(error => { if (active) setStatus(error.message); })
                .finally(() => { if (active) setBusy(false); });
            return () => { active = false; };
        }, []);
        const button = (label, onClick, disabled = false, className = "", attributes = {}) => h("button", {
            ...attributes, type: "button", className, disabled: disabled || busy || !plugin.running || plugin.resetting, onClick
        }, label);
        const copy = async (text, label = "Public key") => {
            try { await navigator.clipboard.writeText(text); setStatus(label + " copied."); }
            catch { setStatus("Select and copy the key manually; clipboard access is unavailable."); }
        };
        const copyIcon = () => h("svg", {width: 24, height: 24, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true, focusable: false},
            h("rect", {width: 14, height: 14, x: 8, y: 8, rx: 2, ry: 2}),
            h("path", {d: "M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"}));
        const copyButton = (label, text, description) => button(h("span", {className: "qcord-copy-label"}, copyIcon(), label), () => copy(text, description));
        const fingerprint = key => plugin.keyId(PQC.createPublicKey(key));
        const partnerIdentity = userId => {
            const profile = plugin.getPartnerProfile(userId);
            return h("span", {className: "qcord-partner-identity"},
                h("span", {className: "qcord-avatar", "aria-hidden": true}, profile.displayName.slice(0, 1).toUpperCase(),
                    profile.avatar && h("img", {src: profile.avatar, alt: "", width: 40, height: 40, loading: "lazy",
                        onError: event => { event.currentTarget.style.display = "none"; }})),
                h("span", null, h("strong", null, profile.displayName), h("span", {className: "qcord-partner-text"}, profile.username),
                    h("span", {className: "qcord-partner-text"}, "user_id: ", h("code", null, userId))));
        };
        const selectPartner = value => { setSelectedChannel(value); setRecipientKey(""); setStatus(""); };
        const saveKey = () => {
            try {
                plugin.saveRecipients(selectedChannel, [{user_id: partner?.userId, public_key_spki_base64: recipientKey}], ACTIVE_SCHEME);
                setPartners(plugin.getSavedPartners());
                setRecipientKey(""); setStatus("DM partner's key saved.");
            } catch (error) { setStatus(error.message); }
        };
        const confirmSave = () => {
            if (!current) { saveKey(); return; }
            try {
                const replacement = fingerprint(recipientKey);
                if (replacement === fingerprint(current.public_key_spki_base64)) { saveKey(); return; }
                BdApi.UI.showConfirmationModal("Replace partner's public key?",
                    "Their fingerprint will change. Verify the new fingerprint with your partner before using it.",
                    {confirmText: "Replace key", cancelText: "Cancel", onConfirm: saveKey});
            } catch (error) { setStatus(error.message); }
        };
        const removeKey = () => {
            try {
                plugin.removePartner(selectedChannel);
                const remaining = plugin.getSavedPartners();
                setPartners(remaining); setRecipientKey("");
                if (selectedChannel !== channelId) setSelectedChannel(openPartner ? channelId : remaining[0]?.channel_id || "");
                setStatus("Partner removed. Other saved partners are unchanged.");
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
                        setPublicKey(""); setCreatedAt(null); setPartners([]); setSelectedChannel(openPartner ? channelId : ""); setRecipientKey("");
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
                    publicKey && h("p", {className: "qcord-fingerprint"}, "Public key fingerprint (SHA-256, 32 bytes): " + fingerprint(publicKey)),
                    publicKey && copyButton("Copy fingerprint", fingerprint(publicKey), "Fingerprint"),
                    h("p", null, "Share this public key in Discord DMs. Keep your private key and config file secret.")),
                h("section", {className: "qcord-section"},
                    h("div", {className: "qcord-heading"}, h("h3", null, "DM partners"), h("span", {className: "qcord-count"}, partners.length + " saved")),
                    h("p", null, "Add contacts from their one-to-one DM. Select a saved contact here to manage their key. Encryption always uses the partner in the DM you send from."),
                    h("div", {className: "qcord-partner-list", role: "group", "aria-label": "Choose a DM partner"},
                        openPartner && !partners.some(row => row.channel_id === channelId) && button(
                            h("span", null, partnerIdentity(openPartner.userId), h("span", {className: "qcord-partner-state"}, "Current DM · Add public key")),
                            () => selectPartner(channelId), false, selectedChannel === channelId ? "qcord-partner-card qcord-selected" : "qcord-partner-card",
                            {"aria-pressed": selectedChannel === channelId}),
                        ...partners.map(row => h("button", {key: row.channel_id, type: "button", className: "qcord-partner-card" + (selectedChannel === row.channel_id ? " qcord-selected" : ""),
                            "aria-pressed": selectedChannel === row.channel_id, disabled: busy || !plugin.running || plugin.resetting, onClick: () => selectPartner(row.channel_id)},
                            partnerIdentity(row.user_id), h("span", {className: "qcord-partner-state"}, row.channel_id === channelId ? "Current DM · Key saved" : "Key saved")))),
                    !partnerUserId && h("p", {className: "qcord-empty"}, "Open a one-to-one DM and reopen this panel to add your first partner. To add another, open their DM and paste their public key here."),
                    partnerUserId && h("div", {className: "qcord-partner-editor"},
                    partnerIdentity(partnerUserId),
                    h("p", {className: "qcord-identifiers"}, "channel_id: ", h("code", null, selectedChannel)),
                    !partner && h("p", null, "Open this partner's DM and reopen the panel to replace their key."),
                    h("label", {className: "qcord-field"}, current ? "Replacement public key" : "Their public key",
                        h("textarea", {rows: 4, value: recipientKey, placeholder: "Paste their ML-KEM-512 public key", disabled: busy || !partner || !plugin.running,
                            onChange: event => setRecipientKey(event.target.value)})),
                    h("div", {className: "qcord-actions"},
                        button(current ? "Replace key" : "Save partner", confirmSave, !partner || !recipientKey.trim())),
                    current && h("div", {className: "qcord-saved-key"},
                        h("p", {className: "qcord-fingerprint"}, "Saved public key fingerprint (SHA-256): " + fingerprint(current.public_key_spki_base64)),
                        h("div", {className: "qcord-actions"},
                            copyButton("Copy saved key", current.public_key_spki_base64),
                            copyButton("Copy fingerprint", fingerprint(current.public_key_spki_base64), "Fingerprint"),
                            button("Remove partner", removeKey))),
                    h("p", null, "Public keys are safe to share here. Verify fingerprints over an independent route, such as a call or in person, to check that the key belongs to your partner.")))),
            status && h("p", {className: "qcord-status", role: "status", "aria-live": "polite"}, status),
            h("details", {className: "qcord-section"}, h("summary", null, "Keys, IDs and message integrity"),
                h("div", {className: "qcord-lessons"},
                    lesson("user_id vs. channel_id", "user_id identifies a Discord account even when its @username changes. channel_id identifies the DM conversation. Qcord reads both from Discord and stores them beside each contact's public key in dm_partners. IDs and avatars identify the Discord account; they do not prove ownership of a key."),
                    lesson("1. ML-KEM establishes a secret", "ML-KEM-512, standardized in FIPS 203 and derived from Kyber, produces a 32-byte shared secret and a 768-byte KEM ciphertext per recipient. Only the matching private key can recover that secret from the KEM ciphertext. ML-KEM does not encrypt your message text or sign it. Using this algorithm does not mean Qcord is FIPS-certified."),
                    lesson("2. HKDF derives a wrapping key", "HKDF-SHA256 turns the ML-KEM shared secret into a 32-byte AES key for wrapping the message key. The shared secret and wrapping key stay local; neither is written into the packet."),
                    lesson("3. AES encrypts the text and message key", "AES-256-GCM encrypts your text with a fresh random 32-byte (256-bit) message key. That same message key is separately encrypted for you and your partner using each recipient's wrapping key. Each AES operation uses a 12-byte nonce and produces a 16-byte authentication tag."),
                    lesson("4. Fingerprints and tags are not signatures", "SHA-256 produces a 32-byte public-key fingerprint, displayed as 64 hexadecimal characters. Compare it to recognize a key. GCM's 16-byte authentication tag detects altered ciphertext and protected metadata. Neither is a digital signature or proof of the sender's identity. Qcord currently has no sender signatures.")),
                h("p", null, "Private keys are stored unencrypted in qcord.config.json. This experimental format has no sender signatures or forward secrecy."),
                h("p", null, "Check your key pair locally, even without a DM partner. This checks cryptography on this device, not Discord delivery.")),
            h("details", {className: "qcord-section"}, h("summary", null, "Read a .qcord packet and config file"),
                h("p", null, "New .qcord files are JSON with tab indentation and new lines. _base64 fields encode binary bytes as text; Base64 is not encryption. Fingerprints are hexadecimal. Your plaintext, private key, shared secret and unwrapped AES message key are never included."),
                h("div", {className: "qcord-lessons"},
                    lesson("Packet header", "qcord_version selects the packet format. kem_algorithm, encryption_algorithm and key_derivation_algorithm name the algorithms. channel_id binds the file to its DM. recipient_key_fingerprints_sha256 lists the keys allowed to decrypt; these fingerprints are not Discord user IDs. The header is authenticated but visible."),
                    lesson("recipients", "Each entry has public_key_fingerprint_sha256 to locate the matching key, kem_ciphertext_base64 for ML-KEM decapsulation, and wrapped_message_key containing that recipient's AES-encrypted copy of the message key. It normally includes your own key and your partner's key."),
                    lesson("encrypted_message and wrapped_message_key", "nonce_base64 is the public 12-byte AES-GCM nonce. ciphertext_base64 is encrypted bytes: message text in encrypted_message, or the 32-byte AES message key in wrapped_message_key. authentication_tag_base64 is the 16-byte tamper-detection tag checked before decryption succeeds."),
                    lesson("qcord.config.json", "encrypt_outgoing_messages and decrypt_incoming_messages are switches. key_pairs stores public_key_spki_base64, private_key_pkcs8_base64 and created_at by algorithm. SPKI and PKCS#8 are DER key containers, encoded as Base64. dm_partners stores channel_id, user_id, key_algorithm, public_key_spki_base64 and saved_at. This local config contains your unencrypted private key; never send it."))),
            h("details", {className: "qcord-section"}, h("summary", null, "Future algorithms"),
                h("p", null, "ML-KEM-768/1024: larger standardized parameter sets. HQC: a code-based KEM selected for standardization, planned for evaluation. ML-DSA/SLH-DSA: signatures for sender verification. No release dates yet."),
                h("a", {href: "https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection", target: "_blank", rel: "noreferrer"}, "NIST: HQC selection")),
            h("div", {className: "qcord-actions"}, button("Clear qcord.config.json", resetConfig, false, "qcord-danger"))
        );
    });
};
