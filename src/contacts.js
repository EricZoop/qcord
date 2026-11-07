"use strict";

const {PQC} = require("./pqc");
const {parameters} = require("./parameters");
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
        return h("dialog", {ref: dialog, className: "qcord-dialog qc-contacts-dialog", "aria-label": "Contacts and keys", onClose, onCancel: () => { /* Native dialog closes on Escape and restores focus. */ }},
            h("div", {className: "qc-panel qc-contacts"},
                h("header", {className: "qc-header"}, h("div", null, h("h2", null, "Contacts & keys"), p("ML-KEM-768 · one local key pair")), button("Close contacts", () => dialog.current.close())),
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
                                h("span", {className: "qc-key-badges"}, h("span", {className: available.length ? "has-key" : ""}, "768")))),
                            () => setSelected(c.id), {key: c.id, className: "qc-contact-card", "aria-pressed": selected === c.id, disabled: busy});
                        }))),
                    h("section", {className: "qc-contact-detail", "aria-label": "Contact key details"},
                        profile ? h(R.Fragment, null,
                            h("div", {className: "qc-person"}, h(Avatar, {profile}), h("div", null, h("h3", null, profile.displayName), p(`${profile.username} · ${selectedContact.userId}`))),
                            h("div", {className: "qc-note"}, row ? `${params.label} public key saved` : `No ${params.label} key saved for this contact.`),
                            row && h(R.Fragment, null, field("Saved public_encaps", h("textarea", {readOnly: true, rows: 3, value: row.public_encaps})),
                                h("div", {className: "qc-row"}, button("Copy contact public key", () => copy(row.public_encaps)), button("Remove contact key", () => { plugin.removePartner(selected, scheme); refresh(); }, {disabled: busy}))),
                            field(`${params.label} public key`, h("textarea", {rows: 3, value: keyText, disabled: busy, placeholder: row ? "Paste a replacement public key" : "Paste the public key your contact shared", onChange: e => setKeyText(e.target.value)})),
                            p("Only ML-KEM-768 keys are accepted: 1184 raw bytes. Verify the shared key with your contact over a trusted route."),
                            h("div", {className: "qc-row"}, button(row ? "Replace public key" : "Save public key", () => run(async () => {
                                const imported = PQC.createPublicKey(keyText);
                                if (!alive.current) return;
                                plugin.saveRecipients(selected, [{user_id: selectedContact.userId, public_encaps: keyText}], imported.asymmetricKeyType);
                                setRows(plugin.getSavedPartners()); onChanged(imported.asymmetricKeyType); setKeyText(""); setNotice(`${imported.asymmetricKeyType.toUpperCase()} contact key saved.`);
                            }), {disabled: busy || !keyText.trim()}),
                            button("Use this recipient", () => { onSelect(selected); dialog.current.close(); }, {className: "qc-primary", disabled: busy || !row})))
                        : h("div", {className: "qc-empty-state"}, h("h3", null, "Choose a contact"), p("Open a one-to-one Discord DM, then choose Add open DM.")))),
                tab === "public" && h("section", {className: "qc-key-page"}, h("h3", null, "Your encapsulation key · ek"),
                    p(`Share this ${params.label} public_encaps. Base64 decodes directly to ${params.publicBytes} FIPS 203 key bytes.`),
                    field("Your public encapsulation key", h("textarea", {readOnly: true, rows: 5, value: keys ? Buffer.from(keys.publicKey.bytes).toString("base64") : "Loading…"})),
                    keys && button("Copy my public key", () => copy(Buffer.from(keys.publicKey.bytes).toString("base64")), {className: "qc-primary"}),
                    p("The corresponding private dk stays on this device.")),
                tab === "private" && h("section", {className: "qc-key-page"}, h("h3", null, "Your decapsulation key · dk"),
                    p(`Your ${params.label} private key is ${params.privateBytes} raw bytes. It is stored unencrypted in qcord.config.json. Never send it to a contact.`),
                    keys && button("Copy private key for backup", () => copy(Buffer.from(keys.privateKey.bytes).toString("base64"))),
                    field("Private decapsulation key to restore", h("textarea", {rows: 3, value: dkText, disabled: busy, onChange: e => { setDkText(e.target.value); setConfirmRestore(false); }})),
                    confirmRestore && h("div", {className: "qc-note", role: "alert"}, `This replaces only your ${params.label} identity. Back up the current dk first; replacing it changes which older files you can open.`),
                    button(confirmRestore ? "Confirm replacement" : "Restore decapsulation key", () => {
                        if (!confirmRestore) { setConfirmRestore(true); return; }
                        run(async () => {
                            const privateKey = PQC.createPrivateKey(dkText), publicKey = PQC.createPublicKey(privateKey);
                            const trial = await PQC.encapsulate(publicKey), recovered = await PQC.decapsulate(privateKey, trial.ciphertext);
                            if (!recovered.equals(trial.sharedKey)) throw new Error("The restored key failed its local check.");
                            recovered.fill(0); trial.sharedKey.fill(0); trial.m.fill(0);
                            if (!alive.current || !plugin.running) return;
                            config.save("public_encaps", Buffer.from(publicKey.bytes).toString("base64"));
                            config.save("private_decaps", Buffer.from(privateKey.bytes).toString("base64"));
                            plugin.session = {}; plugin.keyPairs.get(scheme)?.privateKey.bytes.fill(0); plugin.keyPairs.delete(scheme); plugin.keyTasks.clear();
                            plugin.attachments?.clear(); plugin.scheduleMount?.();
                            await plugin.generateKeys(scheme); onChanged(); setDkText(""); setConfirmRestore(false); setNotice("Key restored. Share its public key with your contacts.");
                        });
                    }, {disabled: busy || !dkText.trim()})),
                h("div", {className: "qc-feedback"}, h("div", {role: "alert", className: "qc-error"}, error), h("div", {role: "status"}, busy ? "Working locally…" : notice)),
                h("footer", {className: "qc-source"}, "FIPS 203 · Public keys identify key bytes; they do not prove identity.")));
    };
};
