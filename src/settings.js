"use strict";

const {PQC} = require("./pqc");
const {ACTIVE_SCHEME} = require("./constants");

module.exports = function getSettingsPanel(plugin) {
    const {createElement: h, useState, useEffect} = BdApi.React;
    const channelId = BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId();
    return h(function Panel() {
        const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
        const [decoding, setDecoding] = useState(plugin.decodeIncoming !== false);
        const scheme = ACTIVE_SCHEME;
        const [publicKey, setPublicKey] = useState("");
        const [recipients, setRecipients] = useState(() => plugin.getRecipients(channelId, plugin.scheme));
        const [username, setUsername] = useState("");
        const [recipientKey, setRecipientKey] = useState("");
        const [busy, setBusy] = useState(true);
        const [status, setStatus] = useState("Loading your encryption key...");
        useEffect(() => {
            let active = true;
            plugin.generateKeys(plugin.scheme).then(keys => {
                if (active) {
                    setPublicKey(keys.publicKey.export({type: "spki", format: "base64"}));
                    setStatus("Encryption key ready and saved locally.");
                }
            }).catch(error => { if (active) setStatus(error.message); })
                .finally(() => { if (active) setBusy(false); });
            return () => { active = false; };
        }, []);
        const button = (label, onClick, disabled = false, variant = "") => h("button", {
            type: "button", className: variant, disabled: disabled || busy || !plugin.running, onClick
        }, label);
        const copy = async text => {
            try { await navigator.clipboard.writeText(text); setStatus("Public key copied."); }
            catch { setStatus("Clipboard unavailable. Select and copy the public key manually."); }
        };
        const paste = async () => {
            try { setRecipientKey(await navigator.clipboard.readText()); setStatus("Public key pasted. Add the recipient to save it."); }
            catch { setStatus("Clipboard unavailable. Paste into the public key field manually."); }
        };
        const loadKey = async () => {
            setBusy(true); setPublicKey(""); setStatus("Loading your encryption key...");
            try {
                const keys = await plugin.generateKeys(scheme);
                setPublicKey(keys.publicKey.export({type: "spki", format: "base64"}));
                setStatus("Encryption key ready and saved locally.");
            }
            catch (error) { setStatus(error.message); }
            finally { setBusy(false); }
        };
        const saveRows = rows => {
            plugin.saveRecipients(channelId, rows, scheme);
            setRecipients(plugin.getRecipients(channelId, scheme));
        };
        const addRecipient = () => {
            try {
                if (!username.trim().replace(/^@/, "")) throw new Error("Enter a username for this public key.");
                saveRows([...recipients, {username: "@" + username.trim().replace(/^@/, ""), publicKey: recipientKey}]);
                setUsername(""); setRecipientKey(""); setStatus("Recipient added and saved.");
            }
            catch (error) { setStatus(error.message); }
        };
        const removeRecipient = index => {
            try { saveRows(recipients.filter((_, i) => i !== index)); setStatus("Recipient removed."); }
            catch (error) { setStatus(error.message); }
        };
        const testAlgorithmNow = async () => {
            setBusy(true); setStatus("Checking ML-KEM-512...");
            try { await plugin.testScheme(scheme, "Qcord encryption check"); setStatus("ML-KEM-512: round-trip passed."); }
            catch (error) { setStatus(error.message); }
            finally { setBusy(false); }
        };
        const cleanPublicKey = value => PQC.createPublicKey(value).export({type: "spki", format: "base64"});
        const toggle = (title, description, checked, onChange) => h("label", {className: "qcord-toggle", "data-checked": checked},
            h("input", {type: "checkbox", checked, disabled: !plugin.running, onChange}),
            h("span", null, h("strong", null, title), h("small", null, description)),
            h("span", {className: "qcord-toggle-state"}, checked ? "On" : "Off"));
        const lesson = (title, text) => h("div", {className: "qcord-lesson"}, h("h4", null, title), h("p", null, text));
        return h("div", {className: "qcord-panel"},
            h("header", {className: "qcord-heading"},
                h("div", null, h("h2", null, "Your private conversation"), h("p", null, "One scheme. Your keys. Post-quantum messaging, explained.")),
                h("span", {className: "qcord-badge"}, "ML-KEM-512")),
            h("section", {className: "qcord-section"},
                h("h3", null, "Messages"),
                h("div", {className: "qcord-switches"},
                    toggle("Encrypt outgoing", "Protect new messages before sending.", enabled,
                        event => { plugin.setEnabled(event.target.checked); setEnabled(plugin.enabled); }),
                    toggle("Decrypt incoming", "Open .qcord files addressed to your keys.", decoding,
                        event => { plugin.setDecoding(event.target.checked); setDecoding(plugin.decodeIncoming); })),
                h("p", {className: "qcord-integrity"}, "Integrity verification is always on for encrypted files. Altered content fails authentication and is not displayed as decrypted text."),
                h("p", null, "Enter prepares an encrypted file. Press Send or Enter again to send it.")
            ),
            h("div", {className: "qcord-workspace"},
            h("section", {className: "qcord-section"},
                h("h3", null, "My encryption key"),
                h("p", null, "Share this public key so others can send you encrypted messages. Your matching private key stays on this device."),
                h("p", null, "Using ML-KEM-512. Previously used another scheme? Exchange ML-KEM-512 keys again. Older keys remain saved for reading past messages."),
                h("label", {className: "qcord-field"}, "My public key", h("textarea", {readOnly: true, rows: 3, value: publicKey, placeholder: "Loading public key..."})),
                h("div", {className: "qcord-actions"},
                    button("Copy my public key", () => copy(publicKey), !publicKey, "qcord-primary"),
                    button("Reload saved key", loadKey)
                ),
                publicKey && h("p", {className: "qcord-fingerprint"}, "SHA-256 fingerprint: " + plugin.keyId(PQC.createPublicKey(publicKey)))
            ),
            h("section", {className: "qcord-section"},
                h("h3", null, "Recipients"),
                h("p", null, channelId ? "Channel " + channelId + " / " + scheme.toUpperCase() : "Open a Discord channel to add recipients."),
                h("p", null, "Usernames are labels, not verified Discord identities. Compare public-key fingerprints with each person before adding them."),
                h("label", {className: "qcord-field"}, "Username", h("input", {
                    type: "text", value: username, maxLength: 100, placeholder: "@username", disabled: busy || !channelId,
                    onChange: event => setUsername(event.target.value)
                })),
                h("label", {className: "qcord-field"}, "Their public key", h("textarea", {
                    rows: 3, value: recipientKey, placeholder: "Paste their ML-KEM-512 public key", disabled: busy || !channelId,
                    onChange: event => setRecipientKey(event.target.value)
                })),
                h("div", {className: "qcord-actions"},
                    button("Paste public key", paste, !channelId),
                    button("Add recipient", addRecipient, !channelId || !username.trim() || !recipientKey.trim(), "qcord-primary")
                ),
                recipients.length ? h("ul", {className: "qcord-recipients"},
                    ...recipients.map((row, index) => h("li", {key: row.publicKey, className: "qcord-recipient"},
                        h("strong", null, row.username || "Saved recipient"),
                        h("details", null, h("summary", null, "View key and fingerprint"),
                            h("p", {className: "qcord-fingerprint"}, plugin.keyId(PQC.createPublicKey(row.publicKey))),
                            h("textarea", {readOnly: true, rows: 3, value: cleanPublicKey(row.publicKey), "aria-label": "Public key for " + (row.username || "saved recipient")})),
                        h("div", {className: "qcord-actions"}, button("Copy key", () => copy(cleanPublicKey(row.publicKey))), button("Remove", () => removeRecipient(index), false, "qcord-danger")))
                    )
                ) : h("p", null, "No recipients for this channel yet. Add an ML-KEM-512 public key above.")
            )
            ),
            h("section", {className: "qcord-section"},
                h("h3", null, "How your message is protected"),
                h("p", null, "Post-quantum cryptography runs on ordinary computers and is designed to resist attacks from future quantum computers. It does not use quantum hardware or quantum key distribution."),
                h("div", {className: "qcord-lessons"},
                    lesson("1 / Public and private keys", "A public key can be shared. ML-KEM-512 uses it to establish a shared secret; only the matching private key can recover that secret from the encapsulation. Never share your private key."),
                    lesson("2 / Encrypt the message", "Qcord encrypts the text with a fresh AES-256-GCM key. Each recipient gets a protected copy of that key using ML-KEM-512 and HKDF-SHA256. Your own key is included so you can read sent messages."),
                    lesson("3 / Verify integrity", "AES-GCM checks an authentication tag before releasing plaintext. Changing protected content causes verification to fail. A plain hash alone would not stop an attacker from changing both a message and its hash."),
                    lesson("4 / Compare key fingerprints", "SHA-256 hashes each public key into a fingerprint. Compare the full fingerprint through a trusted route to confirm the key belongs to the intended person. A fingerprint is not encryption or proof of who sent a message.")),
                h("details", null, h("summary", null, "Check ML-KEM-512 locally"),
                    h("p", null, "Confirm that your saved public and private keys establish the same shared secret."),
                    h("div", {className: "qcord-actions"}, button("Run key check", testAlgorithmNow)))
            ),
            h("details", {className: "qcord-section"},
                h("summary", null, "Coming next / Post-quantum roadmap"),
                h("p", null, "Planned additions, with no release dates yet. ML-KEM-512 is the only option for new conversations today."),
                h("ul", {className: "qcord-roadmap"},
                    h("li", null, h("strong", null, "ML-KEM-768 and ML-KEM-1024"), " — standardized parameter sets with higher security categories and larger keys. Future sending options; older files remain readable."),
                    h("li", null, h("strong", null, "HQC"), " — a code-based KEM selected by NIST for standardization, using a different mathematical foundation from ML-KEM. Planned for evaluation."),
                    h("li", null, h("strong", null, "ML-DSA and SLH-DSA"), " — standardized digital signatures for future sender verification. These authenticate messages; they do not encrypt them.")),
                h("p", null, "Learn more: ",
                    h("a", {href: "https://csrc.nist.gov/pubs/fips/203/final", target: "_blank", rel: "noreferrer"}, "NIST ML-KEM standard"), " · ",
                    h("a", {href: "https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection", target: "_blank", rel: "noreferrer"}, "NIST HQC selection"))
            ),
            h("div", {className: "qcord-status", role: "status", "aria-live": "polite"}, status),
            h("p", null, "Experimental, unaudited messaging. Private keys stay in your local qcord.config.json, stored unencrypted. Keep it private and backed up. Chat files do not verify the sender's identity.")
        );
    });
};
