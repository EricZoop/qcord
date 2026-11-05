"use strict";

const {PQC} = require("./pqc");
const {parameters, PARAMETER_SETS} = require("./parameters");
const config = require("./config");

module.exports = function createContacts(R, ui) {
    const {h, button, field, code, p, Tabs, Avatar} = ui;
    return function Contacts({plugin, scheme, channel, keys, onSelect, onChanged, onClose}) {
        const params = parameters(scheme);
        const [tab, setTab] = R.useState("contacts"), [query, setQuery] = R.useState("");
        const [rows, setRows] = R.useState(() => plugin.getSavedPartners());
        const [selected, setSelected] = R.useState(channel || plugin.currentChannel());
        const [keyText, setKeyText] = R.useState(""), [dkText, setDkText] = R.useState("");
        const [busy, setBusy] = R.useState(false), [error, setError] = R.useState(""), [notice, setNotice] = R.useState("");
        const [confirmRestore, setConfirmRestore] = R.useState(false);
        const dialog = R.useRef(null), alive = R.useRef(true);
        const row = rows.find(r => r.channel_id === selected && r.key_algorithm === scheme);
        const channelIds = [...new Set([...rows.map(r => r.channel_id), selected].filter(Boolean))];
        const contact = id => {
            const existing = rows.find(r => r.channel_id === id);
            try { return {id, userId: existing?.user_id || plugin.getDirectPartner(id).userId}; }
            catch { return null; }
        };
        const selectedContact = contact(selected);
        const profile = selectedContact && plugin.getPartnerProfile(selectedContact.userId);
        R.useEffect(() => {
            dialog.current.showModal();
            const close = () => { alive.current = false; dialog.current?.close(); };
            plugin.dialogs.add(close);
            return () => { alive.current = false; plugin.dialogs.delete(close); };
        }, []);
        R.useEffect(() => { setKeyText(""); setNotice(""); setError(""); }, [selected]);
        async function run(task) {
            if (busy || !alive.current || !plugin.running) return;
            setBusy(true); setError(""); setNotice("");
            try { await task(); } catch (e) { if (alive.current) setError(e.message); }
            finally { if (alive.current) setBusy(false); }
        }
        const copy = text => run(async () => { await navigator.clipboard.writeText(text); if (alive.current) setNotice("Copied."); });
        const refresh = () => { const next = plugin.getSavedPartners(); setRows(next); onChanged(); };
        const fingerprint = row ? plugin.keyId(PQC.createPublicKey(row.public_key_spki_base64)) : null;
        return h("dialog", {ref: dialog, className: "qcord-dialog qc-contacts-dialog", "aria-label": "Contacts and keys", onClose, onCancel: () => { /* Native dialog closes on Escape and restores focus. */ }},
            h("div", {className: "qc-panel qc-contacts"},
                h("header", {className: "qc-header"}, h("div", null, h("h2", null, "Contacts & keys"), p(`${params.label} · each parameter set has its own key pair`)), button("Close contacts", () => dialog.current.close())),
                h(Tabs, {label: "Key manager", items: [["contacts", "Contacts"], ["public", "My public key"], ["private", "Private key"]], value: tab, onChange: v => { setTab(v); setError(""); setNotice(""); }, disabled: busy}),
                tab === "contacts" && h("div", {className: "qc-contact-layout"},
                    h("aside", {className: "qc-contact-sidebar"},
                        field("Search contacts", h("input", {type: "search", value: query, onChange: e => setQuery(e.target.value), placeholder: "Name, username or ID"})),
                        button("Add open DM", () => run(async () => { const id = plugin.currentChannel(); plugin.getDirectPartner(id); setSelected(id); setQuery(""); })),
                        h("div", {className: "qc-contact-list", "aria-label": "Saved contacts"}, channelIds.map(contact).filter(Boolean).filter(c => {
                            const user = plugin.getPartnerProfile(c.userId);
                            return `${user.displayName} ${user.username} ${c.userId}`.toLowerCase().includes(query.toLowerCase());
                        }).map(c => {
                            const user = plugin.getPartnerProfile(c.userId), available = rows.filter(r => r.channel_id === c.id);
                            return button(h(R.Fragment, null, h(Avatar, {profile: user}), h("span", null, h("strong", null, user.displayName), h("small", null, user.username),
                                h("span", {className: "qc-key-badges"}, Object.keys(PARAMETER_SETS).map(s => h("span", {key: s, className: available.some(r => r.key_algorithm === s) ? "has-key" : ""}, s.split("-").pop()))))),
                            () => setSelected(c.id), {key: c.id, className: "qc-contact-card", "aria-pressed": selected === c.id, disabled: busy});
                        }))),
                    h("section", {className: "qc-contact-detail", "aria-label": "Contact key details"},
                        profile ? h(R.Fragment, null,
                            h("div", {className: "qc-person"}, h(Avatar, {profile}), h("div", null, h("h3", null, profile.displayName), p(`${profile.username} · ${selectedContact.userId}`))),
                            h("div", {className: "qc-note"}, row ? `${params.label} public key saved` : `No ${params.label} key saved for this contact.`),
                            fingerprint && h(R.Fragment, null, h("span", {className: "qc-label"}, "SHA-256 fingerprint"), code(fingerprint),
                                h("div", {className: "qc-row"}, button("Copy contact public key", () => copy(row.public_key_spki_base64)), button("Remove this parameter key", () => { plugin.removePartner(selected, scheme); refresh(); }, {disabled: busy}))),
                            field(`${params.label} public key`, h("textarea", {rows: 3, value: keyText, disabled: busy, placeholder: row ? "Paste a replacement public key" : "Paste the public key your contact shared", onChange: e => setKeyText(e.target.value)})),
                            p("Compare fingerprints with your contact over a call or in person before relying on this key."),
                            h("div", {className: "qc-row"}, button(row ? "Replace public key" : "Save public key", () => run(async () => {
                                const imported = PQC.createPublicKey(keyText);
                                if (imported.asymmetricKeyType !== scheme) throw new Error(`This is a ${imported.asymmetricKeyType.toUpperCase()} key. Select that parameter set in the composer first.`);
                                const trial = await PQC.encapsulate(imported); trial.sharedKey.fill(0);
                                if (!alive.current) return;
                                plugin.saveRecipients(selected, [{user_id: selectedContact.userId, public_key_spki_base64: keyText}], scheme);
                                refresh(); setKeyText(""); setNotice("Contact key saved.");
                            }), {disabled: busy || !keyText.trim()}),
                            button("Use this recipient", () => { onSelect(selected); dialog.current.close(); }, {className: "qc-primary", disabled: busy || !row})))
                        : h("div", {className: "qc-empty-state"}, h("h3", null, "Choose a contact"), p("Open a one-to-one Discord DM, then choose Add open DM.")))),
                tab === "public" && h("section", {className: "qc-key-page"}, h("h3", null, "Your encapsulation key · ek"),
                    p(`Share this ${params.label} public key. The raw key is ${params.publicBytes} bytes; the text below includes DER framing and Base64.`),
                    field("Your public encapsulation key", h("textarea", {readOnly: true, rows: 5, value: keys?.publicKey.export({type: "spki", format: "base64"}) || "Loading…"})),
                    keys && h(R.Fragment, null, code(`SHA-256: ${plugin.keyId(keys.publicKey)}`), button("Copy my public key", () => copy(keys.publicKey.export({type: "spki", format: "base64"})), {className: "qc-primary"})),
                    p("The corresponding private dk stays on this device. Changing the parameter set keeps your existing keys.")),
                tab === "private" && h("section", {className: "qc-key-page"}, h("h3", null, "Your decapsulation key · dk"),
                    p(`Your ${params.label} private key is ${params.privateBytes} raw bytes. It is stored unencrypted in qcord.config.json. Never send it to a contact.`),
                    keys && button("Copy private key for backup", () => copy(keys.privateKey.export({type: "pkcs8", format: "base64"}))),
                    field("Private decapsulation key to restore", h("textarea", {rows: 3, value: dkText, disabled: busy, onChange: e => { setDkText(e.target.value); setConfirmRestore(false); }})),
                    confirmRestore && h("div", {className: "qc-note", role: "alert"}, `This replaces only your ${params.label} identity. Back up the current dk first; replacing it changes which older files you can open.`),
                    button(confirmRestore ? "Confirm replacement" : "Restore decapsulation key", () => {
                        if (!confirmRestore) { setConfirmRestore(true); return; }
                        run(async () => {
                            const privateKey = PQC.createPrivateKey(dkText), publicKey = PQC.createPublicKey(privateKey);
                            if (privateKey.asymmetricKeyType !== scheme) throw new Error(`Restore a ${params.label} key, or change parameter sets first.`);
                            const trial = await PQC.encapsulate(publicKey), recovered = await PQC.decapsulate(privateKey, trial.ciphertext);
                            if (!recovered.equals(trial.sharedKey)) throw new Error("The restored key failed its local check.");
                            recovered.fill(0); trial.sharedKey.fill(0);
                            if (!alive.current || !plugin.running) return;
                            config.save("key_pairs", {...config.load("key_pairs"), [scheme]: {public_key_spki_base64: publicKey.export({type: "spki", format: "base64"}), private_key_pkcs8_base64: privateKey.export({type: "pkcs8", format: "base64"}), created_at: new Date().toISOString()}});
                            plugin.session = {}; plugin.keyPairs.delete(scheme); plugin.keyTasks.clear(); plugin.clearDecoded(); plugin.fileDecodes = new WeakMap();
                            await plugin.generateKeys(scheme); onChanged(); setDkText(""); setConfirmRestore(false); setNotice("Key restored. Share its public key with your contacts.");
                        });
                    }, {disabled: busy || !dkText.trim()})),
                h("div", {className: "qc-feedback"}, h("div", {role: "alert", className: "qc-error"}, error), h("div", {role: "status"}, busy ? "Working locally…" : notice)),
                h("footer", {className: "qc-source"}, "Lecture 6 · slides 34, 56, 64, 96 · Public keys identify key bytes; they do not prove identity.")));
    };
};
