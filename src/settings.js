"use strict";

const {PQC} = require("./pqc");
const {KEY_STORE, SCHEMES, KEM_SCHEMES} = require("./constants");

module.exports = function getSettingsPanel(plugin) {
    const {createElement: h, useState, useEffect} = BdApi.React;
    const channelId = BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId();
    return h(function Panel() {
        const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
        const [decoding, setDecoding] = useState(plugin.decodeIncoming !== false);
        const [scheme, setScheme] = useState(plugin.scheme);
        const [publicKey, setPublicKey] = useState("");
        const [recipients, setRecipients] = useState(() => plugin.getRecipients(channelId, plugin.scheme));
        const [username, setUsername] = useState("");
        const [recipientKey, setRecipientKey] = useState("");
        const [testAlgorithm, setTestAlgorithm] = useState(plugin.scheme);
        const [busy, setBusy] = useState(true);
        const [status, setStatus] = useState("Loading your encryption key...");
        useEffect(() => {
            let active = true;
            plugin.generateKeys(plugin.scheme).then(keys => {
                if (active) {
                    setPublicKey(keys.publicKey.export({type: "spki", format: "pem"}));
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
        const loadScheme = async value => {
            setBusy(true); setPublicKey(""); setStatus("Loading your encryption key...");
            plugin.scheme = value;
            BdApi.Data.save(KEY_STORE, "scheme", value);
            setScheme(value); setRecipients(plugin.getRecipients(channelId, value));
            setRecipientKey(""); setUsername("");
            try {
                const keys = await plugin.generateKeys(value);
                setPublicKey(keys.publicKey.export({type: "spki", format: "pem"}));
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
            setBusy(true); setStatus("Checking " + testAlgorithm.toUpperCase() + "...");
            try { await plugin.testScheme(testAlgorithm, "Qcord encryption check"); setStatus(testAlgorithm.toUpperCase() + ": round-trip passed."); }
            catch (error) { setStatus(error.message); }
            finally { setBusy(false); }
        };
        return h("div", {className: "qcord-panel"},
            h("section", {className: "qcord-section"},
                h("h3", null, "Messages"),
                h("label", null, h("input", {
                    type: "checkbox", checked: enabled, disabled: !plugin.running,
                    onChange: event => { plugin.setEnabled(event.target.checked); setEnabled(plugin.enabled); }
                }), "Encrypt outgoing messages"),
                h("label", null, h("input", {
                    type: "checkbox", checked: decoding, disabled: !plugin.running,
                    onChange: event => { plugin.setDecoding(event.target.checked); setDecoding(plugin.decodeIncoming); }
                }), "Decrypt incoming .qcord files"),
                h("p", null, "Enter prepares an encrypted file. Press Send or Enter again to send it.")
            ),
            h("section", {className: "qcord-section"},
                h("h3", null, "My encryption key"),
                h("label", {className: "qcord-field"}, "Scheme and saved key", h("select", {
                    value: scheme, disabled: busy || !plugin.running, onChange: event => loadScheme(event.target.value)
                }, ...KEM_SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase())))),
                h("p", null, "Choosing a scheme loads your saved key or creates one the first time. Your own key is always included in sent files."),
                h("label", {className: "qcord-field"}, "My public key", h("textarea", {readOnly: true, rows: 3, value: publicKey, placeholder: "Loading public key..."})),
                h("div", {className: "qcord-actions"},
                    button("Copy my public key", () => copy(publicKey), !publicKey, "qcord-primary"),
                    button("Reload saved key", () => loadScheme(scheme))
                ),
                publicKey && h("p", {className: "qcord-fingerprint"}, "Fingerprint: " + plugin.keyId(PQC.createPublicKey(publicKey)))
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
                    rows: 3, value: recipientKey, placeholder: "-----BEGIN PUBLIC KEY-----", disabled: busy || !channelId,
                    onChange: event => setRecipientKey(event.target.value)
                })),
                h("div", {className: "qcord-actions"},
                    button("Paste public key", paste, !channelId),
                    button("Add recipient", addRecipient, !channelId || !username.trim() || !recipientKey.trim(), "qcord-primary")
                ),
                recipients.length ? h("div", {className: "qcord-table-scroll"}, h("table", null,
                    h("thead", null, h("tr", null, h("th", {scope: "col"}, "Recipient"), h("th", {scope: "col"}, "Public key"), h("th", {scope: "col"}, "Actions"))),
                    h("tbody", null, ...recipients.map((row, index) => h("tr", {key: row.publicKey},
                        h("td", null, row.username || "Saved recipient"),
                        h("td", null, h("details", null, h("summary", null, "View key and fingerprint"),
                            h("p", {className: "qcord-fingerprint"}, plugin.keyId(PQC.createPublicKey(row.publicKey))),
                            h("textarea", {readOnly: true, rows: 3, value: row.publicKey, "aria-label": "Public key for " + (row.username || "saved recipient")}))),
                        h("td", null, h("div", {className: "qcord-actions"}, button("Copy key", () => copy(row.publicKey)), button("Remove", () => removeRecipient(index), false, "qcord-danger")))
                    )))
                )) : h("p", null, "No recipients for this channel and scheme yet.")
            ),
            h("details", {className: "qcord-section"},
                h("summary", null, "Algorithm check"),
                h("label", {className: "qcord-field"}, "Algorithm", h("select", {
                    value: testAlgorithm, disabled: busy, onChange: event => setTestAlgorithm(event.target.value)
                }, ...SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase() + (KEM_SCHEMES.includes(value) ? " (encryption)" : " (signature check only)"))))),
                h("div", {className: "qcord-actions"}, button("Run check", testAlgorithmNow)),
                h("p", null, "Signature checks do not sign chat messages.")
            ),
            h("div", {className: "qcord-status", role: "status", "aria-live": "polite"}, status),
            h("p", null, "Private keys stay in your local qcord.config.json, stored unencrypted. Keep it private and backed up. Chat files do not verify the sender's identity.")
        );
    });
};
