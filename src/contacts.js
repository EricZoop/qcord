"use strict";

const {PQC} = require("./pqc");
const {ACTIVE_SCHEME} = require("./constants");
const {parameters, PARAMETER_SETS} = require("./parameters");
const config = require("./config");
const dismissOnBackdrop = require("./dialog");
const raw = key => Buffer.from(key.bytes).toString("base64");

module.exports = function createContacts(R, ui) {
    const {h, button, field, code, p, Icon, Avatar, KeyParts} = ui;
    return function Contacts({plugin, channel, keys, view = "contacts", onSelect, onChanged, onClose}) {
        const [ownKeys, setOwnKeys] = R.useState(keys), [level, setLevel] = R.useState(ACTIVE_SCHEME);
        const keyParams = parameters(level);
        const [signatureText, setSignatureText] = R.useState("");
        const tab = view, [query, setQuery] = R.useState("");
        const [rows, setRows] = R.useState(() => plugin.getSavedPartners()), [selected, setSelected] = R.useState(channel || plugin.currentChannel());
        const [keyText, setKeyText] = R.useState(""), [dkText, setDkText] = R.useState("");
        const [signatureRevealed, setSignatureRevealed] = R.useState(false);
        const [revealed, setRevealed] = R.useState(false), [confirmReset, setConfirmReset] = R.useState(false), [confirmRestore, setConfirmRestore] = R.useState(false);
        const [busy, setBusy] = R.useState(false), [error, setError] = R.useState(""), [notice, setNotice] = R.useState("");
        const dialog = R.useRef(null), alive = R.useRef(true), pending = R.useRef(false);
        const row = rows.find(r => r.channel_id === selected);
        const contact = id => { try { return {id, userId: rows.find(r => r.channel_id === id)?.user_id || plugin.getDirectPartner(id).userId}; } catch { return null; } };
        const selectedContact = contact(selected), profile = selectedContact && plugin.getPartnerProfile(selectedContact.userId);
        const channelIds = [...new Set([...rows.map(r => r.channel_id), selected].filter(Boolean))];
        R.useEffect(() => {
            dialog.current.showModal(); const close = () => dialog.current?.close(); plugin.dialogs.add(close);
            const unbind = dismissOnBackdrop(dialog.current, close);
            return () => { alive.current = false; plugin.dialogs.delete(close); unbind(); };
        }, []);
        R.useEffect(() => { setKeyText(row?.public_encaps || ""); setSignatureText(row?.public_signature || ""); setError(""); setNotice(""); }, [selected, row?.public_encaps, row?.public_signature]);
        R.useEffect(() => { if (level === ACTIVE_SCHEME) setOwnKeys(keys); }, [keys]);
        async function run(task) {
            if (pending.current || !alive.current || !plugin.running) return;
            pending.current = true; setBusy(true); setError(""); setNotice("");
            try { await task(); } catch (e) { if (alive.current) setError(e.message); }
            finally { pending.current = false; if (alive.current) setBusy(false); }
        }
        const copy = value => run(async () => { await navigator.clipboard.writeText(value); if (alive.current) setNotice("Copied."); });
        return h("dialog", {ref: dialog, className: "qcord-dialog qc-contacts-dialog", "aria-label": tab === "keys" ? "Your keys" : "Contacts", onClose},
            h("div", {className: "qc-panel qc-contacts"},
                h("header", {className: "qc-contact-header"}, h("h3", {className: "qc-panel-title"}, h(Icon, {name: tab === "keys" ? "keys" : "contacts"}), tab === "keys" ? "Your keys" : "Contacts"),
                    button("Go Back", () => dialog.current.close(), {className: "qc-quiet", title: "Return to the main Qcord panel"})),
                tab === "contacts" ? h("div", {className: "qc-contact-layout"},
                    h("aside", {className: "qc-contact-sidebar"}, h("div", {className: "qc-contact-search"}, h(Icon, {name: "search"}), h("input", {type: "search", "aria-label": "Search contact", value: query, onChange: e => setQuery(e.target.value), placeholder: "Search contact"})),
                        button("Current DM", () => run(async () => { const id = plugin.currentChannel(); plugin.getDirectPartner(id); setSelected(id); setQuery(""); }), {className: "qc-quiet"}),
                        h("div", {className: "qc-contact-list"}, channelIds.map(contact).filter(Boolean).filter(c => { const u = plugin.getPartnerProfile(c.userId); return `${u.displayName} ${u.username}`.toLowerCase().includes(query.toLowerCase()); }).map(c => {
                            const u = plugin.getPartnerProfile(c.userId);
                            return button(h(R.Fragment, null, h(Avatar, {profile: u}), h("span", null, h("strong", null, u.displayName), h("small", null, u.username))), () => { setSelected(c.id); }, {key: c.id, className: "qc-contact-card", "aria-pressed": selected === c.id});
                        }))),
                    h("section", {className: "qc-contact-detail"}, profile ? h(R.Fragment, null,
                        h("div", {className: "qc-person"}, h(Avatar, {profile}), h("div", null, h("h3", null, profile.displayName), p(profile.username))),
                        h("div", {className: "qc-public-keys"}, field("Recipient public key", h("textarea", {rows: 5, value: keyText, disabled: busy, placeholder: "Paste their ML-KEM public key or copied public-key bundle", onChange: e => {
                            const value = e.target.value;
                            try {
                                const bundle = JSON.parse(value);
                                if (typeof bundle.public_encaps === "string" && typeof bundle.public_signature === "string") {
                                    setKeyText(bundle.public_encaps); setSignatureText(bundle.public_signature); return;
                                }
                            } catch { /* Raw Base64 keys are also accepted. */ }
                            setKeyText(value);
                        }})),
                        field("Public signature key", h("textarea", {rows: 3, value: signatureText, disabled: busy, placeholder: "Paste their matching ML-DSA public signature key (optional)", onChange: e => setSignatureText(e.target.value)}))),
                        p("Key length selects the security level automatically: 800, 1184, or 1568 decoded bytes. Save once for this DM."),
                        p("Keep both public keys together for this contact. Signature verification is coming next."),
                        h("div", {className: "qc-row"}, button(row && keyText === row.public_encaps && signatureText === (row.public_signature || "") ? "Saved" : "Save key", () => run(async () => {
                            const publicKey = PQC.createPublicKey(keyText);
                            plugin.saveRecipients(selected, [{user_id: selectedContact.userId, public_encaps: raw(publicKey), public_signature: signatureText}], publicKey.asymmetricKeyType);
                            setRows(plugin.getSavedPartners()); setKeyText(raw(publicKey)); onChanged(); setNotice("Recipient key saved.");
                        }), {className: "qc-primary", disabled: busy || !keyText.trim() || (keyText === row?.public_encaps && signatureText === (row?.public_signature || ""))}),
                        button("Select", () => { onSelect(selected); dialog.current.close(); }, {disabled: busy || !row, className: "qc-action"}),
                        row && button("Clear", () => { plugin.removePartner(selected, row.key_algorithm); setRows(plugin.getSavedPartners()); setKeyText(""); onChanged(); }, {className: "qc-quiet", disabled: busy}))) : p("Open a one-to-one DM to save a recipient."))) :
                h("section", {className: "qc-my-keys"},
                    h("div", {className: "qc-row qc-key-toolbar"},
                    button(`${keyParams.label.replace("ML-KEM-", "ML-KEM ")} / ${keyParams.signature}`, () => run(async () => {
                        const levels = Object.keys(PARAMETER_SETS), next = levels[(levels.indexOf(level) + 1) % levels.length];
                        const pair = await plugin.generateKeys(next);
                        if (alive.current) { setOwnKeys(pair); setLevel(next); setRevealed(false); setSignatureRevealed(false); }
                    }), {className: "qc-action", "aria-label": "Cycle security level", title: "Click to cycle security levels", disabled: busy}),
                    button(h(R.Fragment, null, h(Icon, {name: "copy"}), "Copy both public keys"), () => copy(JSON.stringify({parameter_set: level, public_encaps: raw(ownKeys.publicKey), public_signature: ownKeys.publicSignature}, null, 2)), {disabled: !ownKeys || busy, className: "qc-quiet"})),
                    p(`ML-KEM NIST category ${keyParams.category}. Share the encapsulation and signature public keys from the same level.`),
                    h("div", {className: "qc-public-keys"},
                    h("div", {className: "qc-key-field"},
                        h("div", {className: "qc-label-row"}, h("h3", null, "Public encapsulation key"), button(h(R.Fragment, null, h(Icon, {name: "copy"}), "Copy"), () => copy(raw(ownKeys.publicKey)), {disabled: !ownKeys || busy, className: "qc-quiet"})),
                        h("textarea", {"aria-label": "Public encapsulation key", readOnly: true, rows: 3, value: ownKeys ? raw(ownKeys.publicKey) : "Generating key…"})),
                    h("div", {className: "qc-key-field"},
                        h("div", {className: "qc-label-row"}, h("h3", null, "Public signature key"), button(h(R.Fragment, null, h(Icon, {name: "copy"}), "Copy"), () => copy(ownKeys.publicSignature), {disabled: !ownKeys || busy, className: "qc-quiet"})),
                        h("textarea", {"aria-label": "Public signature key", readOnly: true, rows: 3, value: ownKeys?.publicSignature || "Generating signature key…"}))),
                    h(KeyParts, {k: keyParams.k}),
                    p(`Stored in this order: encoded t̂, then ρ. Together: ${keyParams.publicBytes} bytes / ${4 * Math.ceil(keyParams.publicBytes / 3)} Base64 characters.`),
                    h("p", null, "KeyGen takes random d and computes ", h("span", {className: "qc-inline-math"}, `(ρ, σ) = G(d ∥ byte(${keyParams.k}))`), ". The public seed ρ reconstructs the matrix; secret s and noise e produce the public vector t̂."),
                    h("div", {className: "qc-public-keys qc-private-keys"},
                    h("div", {className: "qc-key-field"},
                        h("div", {className: "qc-label-row"}, h("h3", null, "Private decapsulation key"), h("div", {className: "qc-key-actions"},
                            button(h(R.Fragment, null, h(Icon, {name: "copy"}), "Copy"), () => copy(raw(ownKeys.privateKey)), {className: "qc-quiet qc-private-copy", style: {visibility: revealed ? "visible" : "hidden"}, "aria-label": "Copy private key", title: "Copy private key", disabled: !revealed || !ownKeys || busy}),
                            button(revealed ? "Hide" : "Reveal", () => setRevealed(!revealed), {className: "qc-quiet qc-reveal", disabled: !ownKeys, "aria-label": revealed ? "Hide private key" : "Reveal private key", "aria-expanded": revealed}))),
                        h("div", {className: "qc-private-key", "data-revealed": revealed, onClick: () => ownKeys && setRevealed(true)},
                            h("textarea", {"aria-label": "Private decapsulation key", "aria-hidden": !revealed, tabIndex: revealed ? 0 : -1, readOnly: true, rows: 3, value: ownKeys ? raw(ownKeys.privateKey) : "", onCopy: e => { if (!revealed) e.preventDefault(); }}))),
                    h("div", {className: "qc-key-field"},
                        h("div", {className: "qc-label-row"}, h("h3", null, "Private signature key"), h("div", {className: "qc-key-actions"},
                            button(h(R.Fragment, null, h(Icon, {name: "copy"}), "Copy"), () => copy(ownKeys.privateSignature), {className: "qc-quiet qc-signature-copy", style: {visibility: signatureRevealed ? "visible" : "hidden"}, "aria-label": "Copy private signature key", disabled: !signatureRevealed || !ownKeys || busy}),
                            button(signatureRevealed ? "Hide" : "Reveal", () => setSignatureRevealed(!signatureRevealed), {className: "qc-quiet qc-reveal", disabled: !ownKeys, "aria-label": signatureRevealed ? "Hide private signature key" : "Reveal private signature key", "aria-expanded": signatureRevealed}))),
                        h("div", {className: "qc-private-key", "data-revealed": signatureRevealed, onClick: () => ownKeys && setSignatureRevealed(true)},
                            h("textarea", {"aria-label": "Private signature key", "aria-hidden": !signatureRevealed, tabIndex: signatureRevealed ? 0 : -1, readOnly: true, rows: 3, value: ownKeys?.privateSignature || "", onCopy: e => { if (!signatureRevealed) e.preventDefault(); }})))),
                    h("details", {className: "qc-restore"}, h("summary", null, h(Icon, {name: "chevron"}), "Restore a private key"),
                        field("Private key to restore", h("textarea", {rows: 2, value: dkText, onChange: e => { setDkText(e.target.value); setConfirmRestore(false); }})),
                        confirmRestore && p("This replaces your current identity. Keep a backup of the old key."),
                        button(confirmRestore ? "Confirm replacement" : "Restore key", () => { if (!confirmRestore) { setConfirmRestore(true); return; } run(async () => {
                            const privateKey = PQC.createPrivateKey(dkText), publicKey = PQC.createPublicKey(privateKey);
                            const test = await PQC.encapsulate(publicKey), recovered = await PQC.decapsulate(privateKey, test.ciphertext);
                            try { if (!recovered.equals(test.sharedKey)) throw new Error("This key did not pass its local check."); }
                            finally { recovered.fill(0); test.sharedKey.fill(0); test.m.fill(0); }
                            if (!alive.current || !plugin.running) return;
                            const scheme = privateKey.asymmetricKeyType;
                            config.saveKeySet(scheme, {public_encaps: raw(publicKey), private_decaps: raw(privateKey)});
                            plugin.session = {}; for (const pair of plugin.keyPairs.values()) pair.privateKey.bytes.fill(0); plugin.keyPairs.clear(); plugin.keyTasks.clear(); plugin.attachments?.clear();
                            const restoredKeys = await plugin.generateKeys(scheme); setLevel(scheme); setOwnKeys(restoredKeys); onChanged(); plugin.scheduleMount(); setDkText(""); setConfirmRestore(false); setNotice("Key restored. Share its public key with your contacts.");
                        }); }, {disabled: busy || !dkText.trim(), className: "qc-quiet"})),
                    h("div", {className: "qc-reset-area"}, confirmReset ? h("div", {className: "qc-reset-confirm", role: "alertdialog", "aria-label": "Confirm config reset"},
                        h("strong", null, "Reset keys and clear config?"), p("This removes your current key, contacts, and saved message keys. Old messages need your old backup. A new public key will be generated."),
                        h("div", {className: "qc-row"}, button("Cancel", () => setConfirmReset(false), {disabled: busy}), button(h(R.Fragment, null, h(Icon, {name: "reset"}), "Reset keys"), () => run(() => plugin.clearConfig()), {className: "qc-danger", disabled: busy}))) :
                        button(h(R.Fragment, null, h(Icon, {name: "reset"}), "Clear config & reset key"), () => setConfirmReset(true), {className: "qc-danger", disabled: busy}))),
                (error || notice || busy) && h("div", {className: "qc-feedback"}, h("div", {role: "alert", className: "qc-error"}, error), h("div", {role: "status"}, busy ? "Working…" : notice))));
    };
};
