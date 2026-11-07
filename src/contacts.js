"use strict";

const {PQC} = require("./pqc");
const {ACTIVE_SCHEME} = require("./constants");
const config = require("./config");
const dismissOnBackdrop = require("./dialog");
const raw = key => Buffer.from(key.bytes).toString("base64");

module.exports = function createContacts(R, ui) {
    const {h, button, field, code, p, Icon, Avatar, KeyParts} = ui;
    return function Contacts({plugin, channel, keys, view = "contacts", onSelect, onChanged, onClose}) {
        const tab = view, [query, setQuery] = R.useState("");
        const [rows, setRows] = R.useState(() => plugin.getSavedPartners()), [selected, setSelected] = R.useState(channel || plugin.currentChannel());
        const [keyText, setKeyText] = R.useState(""), [dkText, setDkText] = R.useState("");
        const [revealed, setRevealed] = R.useState(false), [confirmReset, setConfirmReset] = R.useState(false), [confirmRestore, setConfirmRestore] = R.useState(false);
        const [busy, setBusy] = R.useState(false), [error, setError] = R.useState(""), [notice, setNotice] = R.useState("");
        const dialog = R.useRef(null), alive = R.useRef(true), pending = R.useRef(false);
        const row = rows.find(r => r.channel_id === selected);
        const contact = id => { try { return {id, userId: rows.find(r => r.channel_id === id)?.user_id || plugin.getDirectPartner(id).userId}; } catch { return null; } };
        const selectedContact = contact(selected), profile = selectedContact && plugin.getPartnerProfile(selectedContact.userId);
        const channelIds = [...new Set([...rows.map(r => r.channel_id), selected].filter(Boolean))];
        R.useEffect(() => {
            dialog.current.showModal(); const close = () => dialog.current?.close(); plugin.dialogs.add(close);
            const unbind = dismissOnBackdrop(dialog.current, () => plugin.dismissDialogs());
            return () => { alive.current = false; plugin.dialogs.delete(close); unbind(); };
        }, []);
        R.useEffect(() => { setKeyText(row?.public_encaps || ""); setError(""); setNotice(""); }, [selected, row?.public_encaps]);
        async function run(task) {
            if (pending.current || !alive.current || !plugin.running) return;
            pending.current = true; setBusy(true); setError(""); setNotice("");
            try { await task(); } catch (e) { if (alive.current) setError(e.message); }
            finally { pending.current = false; if (alive.current) setBusy(false); }
        }
        const copy = value => run(async () => { await navigator.clipboard.writeText(value); if (alive.current) setNotice("Copied."); });
        return h("dialog", {ref: dialog, className: "qcord-dialog qc-contacts-dialog", "aria-label": tab === "keys" ? "Your keys" : "Contacts", onClose},
            h("div", {className: "qc-panel qc-contacts"},
                h("header", {className: "qc-contact-header"}, h("h3", {className: "qc-panel-title"}, h(Icon, {name: tab === "keys" ? "keys" : "contacts"}), tab === "keys" ? "Your keys" : "Contacts"), button(h(Icon, {name: "close"}), () => dialog.current.close(), {className: "qc-icon-button", "aria-label": tab === "keys" ? "Close keys" : "Close contacts"})),
                tab === "contacts" ? h("div", {className: "qc-contact-layout"},
                    h("aside", {className: "qc-contact-sidebar"}, field("Search contacts", h("input", {type: "search", value: query, onChange: e => setQuery(e.target.value), placeholder: "Find a contact…"})),
                        button("Current DM", () => run(async () => { const id = plugin.currentChannel(); plugin.getDirectPartner(id); setSelected(id); setQuery(""); onSelect(id); }), {className: "qc-quiet"}),
                        h("div", {className: "qc-contact-list"}, channelIds.map(contact).filter(Boolean).filter(c => { const u = plugin.getPartnerProfile(c.userId); return `${u.displayName} ${u.username}`.toLowerCase().includes(query.toLowerCase()); }).map(c => {
                            const u = plugin.getPartnerProfile(c.userId);
                            return button(h(R.Fragment, null, h(Avatar, {profile: u}), h("span", null, h("strong", null, u.displayName), h("small", null, u.username))), () => { setSelected(c.id); onSelect(c.id); }, {key: c.id, className: "qc-contact-card", "aria-pressed": selected === c.id});
                        }))),
                    h("section", {className: "qc-contact-detail"}, profile ? h(R.Fragment, null,
                        h("div", {className: "qc-person"}, h(Avatar, {profile}), h("div", null, h("h3", null, profile.displayName), p(profile.username))),
                        field("Recipient public key", h("textarea", {rows: 5, value: keyText, disabled: busy, placeholder: "Paste their ML-KEM-768 public key", onChange: e => setKeyText(e.target.value)})),
                        p("1184 raw bytes · 1580 Base64 characters. Save once for this DM."),
                        h("div", {className: "qc-row"}, button(row && keyText === row.public_encaps ? "Saved" : "Save key", () => run(async () => {
                            const publicKey = PQC.createPublicKey(keyText);
                            plugin.saveRecipients(selected, [{user_id: selectedContact.userId, public_encaps: raw(publicKey)}]);
                            setRows(plugin.getSavedPartners()); setKeyText(raw(publicKey)); onChanged(); onSelect(selected); setNotice("Recipient key saved.");
                        }), {className: "qc-primary", disabled: busy || !keyText.trim() || keyText === row?.public_encaps}),
                        row && button("Remove", () => { plugin.removePartner(selected); setRows(plugin.getSavedPartners()); setKeyText(""); onChanged(); }, {className: "qc-quiet", disabled: busy}))) : p("Open a one-to-one DM to save a recipient."))) :
                h("section", {className: "qc-my-keys"},
                    h("div", {className: "qc-label-row"}, h("h3", null, "Public encapsulation key"), button("Copy", () => copy(raw(keys.publicKey)), {disabled: !keys || busy, className: "qc-quiet"})),
                    field("Your public encapsulation key", h("textarea", {readOnly: true, rows: 3, value: keys ? raw(keys.publicKey) : "Generating key…"})),
                    h(KeyParts),
                    p("Stored in this order: encoded t̂, then ρ. Together: 1184 bytes / 1580 Base64 characters."),
                    p("KeyGen takes random d and computes (ρ, σ) = G(d ∥ byte(3)). The public seed ρ reconstructs Â; secret s and noise e produce t̂ = Â ∘ ŝ + ê."),
                    h("div", {className: "qc-secret"},
                        h("div", {className: "qc-label-row"}, h("strong", null, "Private decapsulation key"), button(revealed ? "Hide" : "Reveal", () => setRevealed(!revealed), {className: "qc-quiet", disabled: !keys, "aria-expanded": revealed})),
                        revealed ? h(R.Fragment, null, field("Your private decapsulation key", h("textarea", {readOnly: true, rows: 3, value: keys ? raw(keys.privateKey) : ""})), button("Copy private key", () => copy(raw(keys.privateKey)), {className: "qc-quiet", disabled: !keys || busy})) :
                            button(h(R.Fragment, null, h("span", {className: "qc-secret-mask", "aria-hidden": true}, "•••• •••• •••• •••• •••• ••••"), h("small", null, "Click to reveal · keep private")), () => setRevealed(true), {className: "qc-spoiler", disabled: !keys, "aria-label": "Reveal private key"})),
                    h("details", {className: "qc-restore"}, h("summary", null, "Restore a private key"),
                        field("Private key to restore", h("textarea", {rows: 2, value: dkText, onChange: e => { setDkText(e.target.value); setConfirmRestore(false); }})),
                        confirmRestore && p("This replaces your current identity. Keep a backup of the old key."),
                        button(confirmRestore ? "Confirm replacement" : "Restore key", () => { if (!confirmRestore) { setConfirmRestore(true); return; } run(async () => {
                            const privateKey = PQC.createPrivateKey(dkText), publicKey = PQC.createPublicKey(privateKey);
                            const test = await PQC.encapsulate(publicKey), recovered = await PQC.decapsulate(privateKey, test.ciphertext);
                            try { if (!recovered.equals(test.sharedKey)) throw new Error("This key did not pass its local check."); }
                            finally { recovered.fill(0); test.sharedKey.fill(0); test.m.fill(0); }
                            if (!alive.current || !plugin.running) return;
                            config.save("public_encaps", raw(publicKey)); config.save("private_decaps", raw(privateKey));
                            plugin.session = {}; plugin.keyPairs.get(ACTIVE_SCHEME)?.privateKey.bytes.fill(0); plugin.keyPairs.clear(); plugin.keyTasks.clear(); plugin.attachments?.clear();
                            await plugin.generateKeys(); onChanged(); plugin.scheduleMount(); setDkText(""); setConfirmRestore(false); setNotice("Key restored. Share its public key with your contacts.");
                        }); }, {disabled: busy || !dkText.trim(), className: "qc-quiet"})),
                    h("div", {className: "qc-reset-area"}, confirmReset ? h("div", {className: "qc-reset-confirm", role: "alertdialog", "aria-label": "Confirm config reset"},
                        h("strong", null, "Reset keys and clear config?"), p("This removes your current key, contacts, and saved m values. Old messages need your old backup. A new public key will be generated."),
                        h("div", {className: "qc-row"}, button("Cancel", () => setConfirmReset(false), {disabled: busy}), button("Reset keys", () => run(() => plugin.clearConfig()), {className: "qc-danger", disabled: busy}))) :
                        button("Clear config & reset key", () => setConfirmReset(true), {className: "qc-danger", disabled: busy}))),
                (error || notice || busy) && h("div", {className: "qc-feedback"}, h("div", {role: "alert", className: "qc-error"}, error), h("div", {role: "status"}, busy ? "Working…" : notice))));
    };
};
