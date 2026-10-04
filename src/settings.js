"use strict";

const { Crypto, PQC } = require("./pqc");
const { KEY_STORE, SCHEMES, KEM_SCHEMES } = require("./constants");

module.exports = function getSettingsPanel(plugin) {
    const {createElement: h, useState, useEffect} = BdApi.React;
    const channelId = BdApi.Webpack.getStore?.("SelectedChannelStore")?.getChannelId();
    const savedRecipients = BdApi.Data.load(KEY_STORE, "recipients")?.[channelId];
    const versions = typeof process === "object" ? process.versions || {} : {};
    const canGenerate = typeof Crypto?.randomBytes === "function";
    return h(function Panel() {
        const [enabled, setEnabled] = useState(Boolean(plugin.enabled));
        const [decoding, setDecoding] = useState(plugin.decodeIncoming !== false);
        const [scheme, setScheme] = useState(plugin.scheme);
        const [testAlgorithm, setTestAlgorithm] = useState(plugin.scheme);
        const [publicKey, setPublicKey] = useState("");
        const [recipientText, setRecipientText] = useState(savedRecipients?.scheme === plugin.scheme ? savedRecipients.publicKeys.join("\n") : "");
        const [sample, setSample] = useState("Qcord PQC round-trip test");
        const [busy, setBusy] = useState(true);
        const [status, setStatus] = useState("Loading or generating your encryption key...");
        const [elapsed, setElapsed] = useState(0);
        useEffect(() => {
            let active = true;
            plugin.generateKeys(plugin.scheme).then(keys => {
                if (active) {
                    setPublicKey(keys.publicKey.export({type: "spki", format: "pem"}));
                    setStatus("Encryption key ready and saved locally.");
                }
            }).catch(error => {
                if (active) setStatus(error.message);
            }).finally(() => { if (active) setBusy(false); });
            return () => { active = false; };
        }, []);
        useEffect(() => {
            if (!busy) return;
            const started = performance.now();
            setElapsed(0);
            const timer = setInterval(() => setElapsed(performance.now() - started), 100);
            return () => clearInterval(timer);
        }, [busy]);
        const loadKeys = async value => {
            setBusy(true); setStatus("Loading or generating encryption keys...");
            try {
                const keys = await plugin.generateKeys(value);
                setPublicKey(keys.publicKey.export({type: "spki", format: "pem"}));
                setStatus("Encryption key ready and saved locally.");
            }
            catch (error) { setPublicKey(""); setStatus(error.message); }
            finally { setBusy(false); }
        };
        const runTests = async algorithms => {
            setBusy(true);
            for (const algorithm of algorithms) {
                if (!plugin.running) break;
                setStatus("Testing " + algorithm.toUpperCase() + "...");
                try { await plugin.testScheme(algorithm, sample); }
                catch (error) { plugin.schemeStatus[algorithm] = error.message; }
            }
            setStatus("Tests finished. See algorithm results below."); setBusy(false);
        };
        const metrics = plugin.metrics;
        const ms = value => Number.isFinite(value) ? value.toFixed(3) + " ms" : "not measured";
        const timingLines = [];
        if (metrics.keygen) timingLines.push("Key generation (saved measurement): " + metrics.keygen.scheme + ", " + ms(metrics.keygen.ms) +
            "; public " + metrics.keygen.publicBytes + " B, private " + metrics.keygen.privateBytes + " B (DER)");
        if (metrics.encrypt) timingLines.push("Last encryption: " + ms(metrics.encrypt.ms) + "; " + metrics.encrypt.inputBytes + " B text -> " + metrics.encrypt.fileBytes + " B file; " + metrics.encrypt.recipients + " keys");
        if (metrics.decrypt) timingLines.push("Last decryption: " + ms(metrics.decrypt.ms) + "; " + metrics.decrypt.fileBytes + " B file -> " + metrics.decrypt.inputBytes + " B text");
        if (metrics.test?.encapsulateMs !== undefined) timingLines.push("Last KEM test: " + metrics.test.scheme + "; encapsulate " + ms(metrics.test.encapsulateMs) + ", decapsulate " + ms(metrics.test.decapsulateMs) + "; " + metrics.test.kemBytes + " B KEM ciphertext");
        if (metrics.test?.signMs !== undefined) timingLines.push("Last signature test: " + metrics.test.scheme + "; sign " + ms(metrics.test.signMs) + ", verify " + ms(metrics.test.verifyMs) + "; " + metrics.test.signatureBytes + " B signature for " + metrics.test.inputBytes + " B input");
        return h("div", {className: "qcord-panel"},
            h("label", null, h("input", {
                type: "checkbox", checked: enabled, disabled: !plugin.running,
                onChange: event => { plugin.setEnabled(event.target.checked); setEnabled(plugin.enabled); }
            }), "Encrypt outgoing messages"),
            h("label", null, h("input", {
                type: "checkbox", checked: decoding, disabled: !plugin.running,
                onChange: event => { plugin.setDecoding(event.target.checked); setDecoding(plugin.decodeIncoming); }
            }), "Decrypt incoming messages (also decode older Base64)"),
            h("p", null, "Runtime: Node " + (versions.node || "unavailable") + "; OpenSSL " + (versions.openssl || "unavailable") +
                "; AES/HKDF " + (Crypto?.createCipheriv && Crypto?.hkdfSync ? "available" : "unavailable") + "; PQC: " + PQC.backend),
            h("label", {className: "qcord-field"}, "Chat encryption scheme", h("select", {
                value: scheme, disabled: busy || !plugin.running,
                onChange: event => {
                    const value = event.target.value;
                    plugin.scheme = value; BdApi.Data.save(KEY_STORE, "scheme", value); setScheme(value);
                    const recipients = BdApi.Data.load(KEY_STORE, "recipients")?.[channelId];
                    setRecipientText(recipients?.scheme === value ? recipients.publicKeys.join("\n") : "");
                    loadKeys(value);
                }
            }, ...KEM_SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase())))),
            h("button", {type: "button", disabled: busy || !plugin.running || !canGenerate, onClick: () => loadKeys(scheme)}, "Load/generate my encryption key"),
            publicKey && h("label", {className: "qcord-field"}, "My public encryption key (share this)", h("textarea", {readOnly: true, rows: 4, value: publicKey})),
            publicKey && h("p", null, "SHA-256 fingerprint: " + plugin.keyId(PQC.createPublicKey(publicKey))),
            h("label", {className: "qcord-field"}, "Recipient public keys for channel " + (channelId || "(none selected)"), h("textarea", {
                rows: 4, value: recipientText, disabled: busy || !channelId,
                placeholder: "Paste each recipient's complete PUBLIC KEY PEM block here.",
                onChange: event => setRecipientText(event.target.value)
            })),
            h("button", {type: "button", disabled: busy || !channelId || !Crypto,
                onClick: () => {
                    try { plugin.saveRecipients(channelId, recipientText, scheme); setStatus("Recipient keys saved for this channel."); }
                    catch (error) { setStatus(error.message); }
                }
            }, "Save recipient keys"),
            h("p", null, "Verify public-key fingerprints with your recipients before saving. Use the same ML-KEM scheme. Your own key is included automatically so you can read sent files."),
            h("p", null, "Private keys are saved unencrypted in local qcord.config.json. Keep that file private and backed up. These experimental files do not authenticate the sender's identity."),
            h("label", {className: "qcord-field"}, "Bundled PQC algorithm test", h("select", {
                value: testAlgorithm, disabled: busy,
                onChange: event => setTestAlgorithm(event.target.value)
            }, ...SCHEMES.map(value => h("option", {key: value, value}, value.toUpperCase() + (KEM_SCHEMES.includes(value) ? " (KEM)" : " (signature)"))))),
            h("label", {className: "qcord-field"}, "Signature test text", h("textarea", {rows: 2, value: sample, disabled: busy, onChange: event => setSample(event.target.value)})),
            h("button", {type: "button", disabled: busy || !plugin.running || !canGenerate, onClick: () => runTests([testAlgorithm])}, "Test selected algorithm"),
            h("button", {type: "button", disabled: busy || !plugin.running || !canGenerate, onClick: () => runTests(SCHEMES)}, "Test all listed algorithms"),
            h("div", {role: "status"}, busy ? status + " " + elapsed.toFixed(0) + " ms elapsed" : status),
            h("pre", null, SCHEMES.map(value => value + ": " + (plugin.schemeStatus[value] || "not tested")).join("\n")),
            h("pre", null, timingLines.join("\n") || "No timings yet."),
            h("p", null, "Timings are local elapsed milliseconds, including async scheduling. Encryption excludes key generation; decryption excludes download. CPU clock cycles are unavailable through this JavaScript API."),
            h("p", null, "ML-KEM, ML-DSA and SLH-DSA are standardized PQC families. This build includes these seven schemes; other candidates are not enabled. Signature tests do not encrypt text.")
        );
    });
};
