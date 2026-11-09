"use strict";

const {PQC} = require("./pqc");
const {sha3_256, sha3_512} = require("@noble/hashes/sha3.js");
const {ACTIVE_SCHEME, MAX_DECODED_FILE_SIZE} = require("./constants");
const M = require("./mlkem");
const createUI = require("./ui");
const createContacts = require("./contacts");
const dismissOnBackdrop = require("./dialog");
const hex = bytes => Buffer.from(bytes).toString("hex");
const stages = ["Recipient key", "Derive K", "Construct u, v", "Message & attach"];

module.exports = function getSettingsPanel(plugin, {onClose} = {}) {
    const R = BdApi.React, ui = createUI(R);
    const {h, p, button, field, formula, code, Icon, Tabs, Switch, Avatar, Variables, Sparkline, KeyParts, Polynomial} = ui;
    const Contacts = createContacts(R, ui);
    const split = (left, right, className = "") => h("div", {className: `qc-split ${className}`}, h("section", {className: "qc-explanation"}, left), h("section", {className: "qc-visual"}, right));

    function OpenedMessage({result, onDismiss}) {
        const dialog = R.useRef(null);
        R.useEffect(() => {
            dialog.current.showModal(); const close = () => dialog.current?.close(); plugin.dialogs.add(close);
            const unbind = dismissOnBackdrop(dialog.current, close);
            return () => { plugin.dialogs.delete(close); unbind(); };
        }, []);
        return h("dialog", {ref: dialog, className: "qcord-dialog qc-opened-dialog", "aria-label": "Decrypted message", onClose: onDismiss},
            h("div", {className: "qc-panel"}, h("div", {className: "qc-label-row"}, h("span", {className: "qc-muted"}, result.source), h("div", {className: "qc-row"},
                button("Go Back", () => dialog.current.close(), {className: "qc-quiet", title: "Return to the main Qcord panel"}))),
                h("div", {className: `qc-plaintext qcord-message ${plugin.markupClass}`}, plugin.messageContent(result.text, plugin.currentChannel())),
                h("details", null, h("summary", null, "Derived K"), code(result.key))));
    }

    function Panel() {
        const [step, setStep] = R.useState(0), [text, setText] = R.useState("");
        const [channel, setChannel] = R.useState(() => plugin.currentChannel() || "");
        const [partners, setPartners] = R.useState(() => plugin.getSavedPartners()), [keys, setKeys] = R.useState(null);
        const [draft, setDraft] = R.useState(null), [messageReady, setMessageReady] = R.useState(false);
        const [opened, setOpened] = R.useState(null), [contactsTab, setContactsTab] = R.useState(null);
        const [busy, setBusy] = R.useState(false), [error, setError] = R.useState(""), [notice, setNotice] = R.useState("");
        const [attached, setAttached] = R.useState(false), [stopped, setStopped] = R.useState(!plugin.running);
        const [autoEncrypt, setAutoEncrypt] = R.useState(plugin.autoEncrypt), [autoDecrypt, setAutoDecrypt] = R.useState(plugin.autoDecrypt);
        const [keyTab, setKeyTab] = R.useState("matrix"), [part, setPart] = R.useState("u");
        const [vectorIndex, setVectorIndex] = R.useState(0), [matrixCell, setMatrixCell] = R.useState(0), [coefficient, setCoefficient] = R.useState(0);
        const alive = R.useRef(true), ticket = R.useRef(0), pending = R.useRef(false), preview = R.useRef(null), filePicker = R.useRef(null);
        const indices = [0, 1, 2], row = partners.find(r => r.channel_id === channel);
        const profile = row ? plugin.getPartnerProfile(row.user_id) : null;
        const publicInfo = R.useMemo(() => row ? M.publicTrace(PQC.createPublicKey(row.public_encaps).bytes) : null, [row?.public_encaps]);
        const derived = R.useMemo(() => {
            if (!draft) return null;
            const kr = sha3_512(Uint8Array.from([...draft.trace.m, ...sha3_256(PQC.createPublicKey(draft.public_encaps).bytes)]));
            try { return {k: hex(kr.slice(0, 32)), r: hex(kr.slice(32))}; } finally { kr.fill(0); }
        }, [draft?.trace.m, draft?.public_encaps]);
        R.useEffect(() => {
            const stop = () => { alive.current = false; ticket.current++; M.wipe(preview.current); setDraft(null); setKeys(null); setStopped(true); };
            const reset = value => { invalidate(); setPartners([]); setKeys(value); setText(""); setOpened(null); setContactsTab(null); setStep(0); setNotice("New key ready. Share your public key with contacts."); };
            const modes = () => { setAutoEncrypt(plugin.autoEncrypt); setAutoDecrypt(plugin.autoDecrypt); };
            plugin.panels.add(stop); plugin.resets.add(reset); plugin.modeListeners.add(modes);
            return () => { alive.current = false; ticket.current++; M.wipe(preview.current); plugin.panels.delete(stop); plugin.resets.delete(reset); plugin.modeListeners.delete(modes); };
        }, []);
        R.useEffect(() => {
            let active = true;
            plugin.generateKeys().then(value => { if (active && alive.current) setKeys(value); }).catch(e => { if (active && alive.current) setError(e.message); });
            return () => { active = false; };
        }, [partners]);
        function invalidate() { ticket.current++; M.wipe(preview.current); preview.current = null; setDraft(null); setMessageReady(false); setAttached(false); setError(""); setNotice(""); }
        async function run(task) {
            if (pending.current || !alive.current || !plugin.running) return;
            pending.current = true; setBusy(true); setError(""); setNotice("");
            try { await task(); } catch (e) { if (alive.current) setError(e.message); }
            finally { pending.current = false; if (alive.current) setBusy(false); }
        }
        async function prepare(target, fresh = false) {
            if (!row) throw new Error("Save your recipient's public key first.");
            if (draft && !fresh) { setStep(target); return; }
            invalidate(); const request = ++ticket.current;
            const result = await plugin.prepareEncapsulation(channel, ACTIVE_SCHEME, text);
            if (!alive.current || request !== ticket.current) { M.wipe(result); return; }
            preview.current = result; setDraft(result); setMessageReady(text.length > 0); setStep(target);
        }
        const navigate = value => {
            if (value === step) return;
            if (value === 0 || draft) { setStep(value); return; }
            run(() => prepare(value));
        };
        const refreshed = () => { invalidate(); setPartners(plugin.getSavedPartners()); setStep(0); };
        function editMessage(value) {
            setText(value); setAttached(false); setError(""); setMessageReady(false);
            try { const next = plugin.updateDraftMessage(preview.current, value); preview.current = next; setDraft(next); setMessageReady(value.length > 0); }
            catch (e) { setError(e.message); }
        }
        const vectorTiles = (polynomials, label, selected, select) => h("div", {className: "qc-vector-tiles", "aria-label": `${label} vector`}, polynomials.map((values, i) => button(h(R.Fragment, null, h("span", null, `${label}[${i}]`), h(Sparkline, {values})), () => select(i), {key: i, "aria-pressed": selected === i})));
        let content;
        if (step === 0) {
            const selected = keyTab === "vector" ? publicInfo?.tHat[vectorIndex] : publicInfo?.aHat[Math.floor(matrixCell / 3)][matrixCell % 3];
            content = split(h(R.Fragment, null, h(Variables, {items: [["ek", "recipient's public key"], ["k / n / q", "3 / 256 / 3329"], ["t̂", "3 public polynomials"], ["ρ", "32-byte public seed"]]}),
                h("h3", null, "Read the recipient's key"), formula("ek = ByteEncode₁₂(t̂) ∥ ρ"), h(KeyParts),
                p("The first 1152 bytes encode t̂. The last 32 bytes are ρ, which reconstructs the 3 × 3 matrix Â."),
                code("Â[i,j] = SampleNTT(ρ ∥ byte(j) ∥ byte(i))"),
                !row && button("Add recipient's public key", () => setContactsTab("contacts"), {className: "qc-primary"})),
            h(R.Fragment, null, h(Tabs, {label: "Public key views", items: [["matrix", "Matrix Â"], ["vector", "Vector t̂"], ["saved", "Encoded key"]], value: keyTab, onChange: setKeyTab}),
                keyTab === "saved" ? h(R.Fragment, null, field("Saved public_encaps", h("textarea", {rows: 5, readOnly: true, value: row?.public_encaps || "Save a recipient key to inspect its bytes."})), p("1184 raw bytes · 1580 Base64 characters")) :
                h(R.Fragment, null, keyTab === "matrix" ? h("div", {className: "qc-matrix", "aria-label": "Public matrix A hat"}, indices.flatMap(i => indices.map(j => button(h(R.Fragment, null, h("span", null, `Â[${i},${j}]`), h(Sparkline, {values: publicInfo?.aHat[i][j]})), () => setMatrixCell(i * 3 + j), {key: `${i}-${j}`, "aria-pressed": matrixCell === i * 3 + j, disabled: !publicInfo})))) :
                    vectorTiles(publicInfo?.tHat || [[], [], []], "t̂", vectorIndex, setVectorIndex),
                    selected ? h(Polynomial, {values: selected, name: keyTab === "vector" ? `t̂[${vectorIndex}] · NTT` : `Â[${Math.floor(matrixCell / 3)},${matrixCell % 3}] · NTT`}) : h("div", {className: "qc-awaiting"}, p("Each cell is a polynomial of 256 coefficients."), p("Your recipient's values appear here after you save their key.")))));
        }
        if (step === 1 && draft) {
            content = split(h(R.Fragment, null, h(Variables, {items: [["m", "fresh random 32 bytes"], ["ek", "recipient key · 1184 bytes"], ["H", "SHA3-256"], ["G", "SHA3-512"]]}),
                h("h3", null, "Derive the shared key"), formula("(K, r) = G(m ∥ H(ek))"),
                p("Hash the entire public key. Split G's 64-byte output: the first 32 bytes are K; the last 32 are the noise seed r."),
                formula("μ = Decompress₁(ByteDecode₁(m))"), p("μ encodes m as 256 coefficients: a 0 bit becomes 0, a 1 bit becomes 1665."),
                button(h(R.Fragment, null, h(Icon, {name: "reset"}), "Sample fresh m"), () => run(() => prepare(1, true)), {disabled: busy, className: "qc-action", title: "Generate fresh randomness and rebuild this encapsulation"})),
            h(R.Fragment, null, h("div", {className: "qc-secret-values"}, code(`m · ${hex(draft.trace.m)}`), code(`K · ${derived.k}`), code(`r · ${derived.r}`)), h(Polynomial, {values: draft.trace.mu, name: "μ · encoded m"})));
        }
        if (step === 2 && draft) {
            const t = draft.trace, i = vectorIndex, j = coefficient, values = part === "u" ? t.u[i] : t.v;
            const product = part === "u" ? M.mod(values[j] - t.e1[i][j]) : M.mod(values[j] - t.e2[j] - t.mu[j]);
            content = split(h(R.Fragment, null, h(Variables, {items: [["r", "32-byte sampling seed from (K, r)"], ["Â / t̂", "recipient public polynomials in NTT form"], ["y / e₁ / e₂", "3 / 3 / 1 polynomials, sampled from r"], ["μ", "m encoded as coefficients 0 or 1665"]]}),
                h("section", {className: "qc-sampling", "aria-label": "Noise sampling from r"},
                    h("div", {className: "qc-seed-row"}, h("strong", null, "Seed r"), h("code", {"aria-label": "Sampling seed r"}, derived.r)),
                    h("div", {className: "qc-noise-paths"}, [["y[0..2]", "0, 1, 2"], ["e₁[0..2]", "3, 4, 5"], ["e₂", "6"]].map(([symbol, nonces]) => h("div", {key: symbol}, h("strong", null, symbol), h("small", null, `Nonce N = ${nonces}`)))),
                    h("div", {className: "qc-sampling-equation", role: "math"}, "Each polynomial = SamplePolyCBD₂(PRF₂(r, N))"),
                    h("small", null, "r is a seed, not the vector y. Then compute ŷ = NTT(y).")),
                h("div", {className: "qc-construction-equations"}, formula("u = NTT⁻¹(Âᵀ ∘ ŷ) + e₁"), formula("v = NTT⁻¹(t̂ᵀ ∘ ŷ) + μ + e₂"),
                    h("small", null, "∘ multiplies in the NTT domain. Coefficients are modulo 3329.")),
                code(part === "u" ? `u[${i}][${j}] = (${product} + ${t.e1[i][j]}) mod 3329 = ${values[j]}` : `v[${j}] = (${product} + ${t.mu[j]} + ${t.e2[j]}) mod 3329 = ${values[j]}`),
                h("div", {className: "qc-compression"}, h("span", null, "Compressed for the file"), h("strong", null, `${values[j]} → ${M.compress(values[j], part === "u" ? 10 : 4)}`), h("small", null, part === "u" ? "10 bits" : "4 bits")),
                h("details", {className: "qc-noise-details"}, h("summary", null, "Sampled coefficients"), code(`y[${i}]: ${t.rVector[i].slice(0, 12).join(", ")} …\ne₁[${i}]: ${t.e1[i].slice(0, 12).join(", ")} …\ne₂: ${t.e2.slice(0, 12).join(", ")} …`))),
            h(R.Fragment, null, h(Tabs, {label: "Ciphertext components", items: [["u", "Compute u"], ["v", "Compute v"]], value: part, onChange: setPart}),
                part === "u" ? vectorTiles(t.u, "u", i, setVectorIndex) : h("figure", {className: "qc-single-polynomial", "aria-label": "v polynomial overview"}, h("figcaption", null, h("strong", null, "v"), h("small", null, "One polynomial · 256 coefficients")), h(Sparkline, {values: t.v})),
                h(Polynomial, {values, name: part === "u" ? `u[${i}] · before compression` : "v · before compression", index: j, onIndexChange: setCoefficient}),
                h("span", {className: "qc-muted"}, "The compressed values match the library's ciphertext byte for byte.")), "qc-construction");
        }
        if (step === 3 && draft) {
            content = split(h(R.Fragment, null, h(Variables, {items: [["K", "32-byte shared secret"], ["nonce", "12 fresh random bytes"], ["tag", "16-byte authentication tag"]]}),
                h("h3", null, "Write the encrypted message"),
                field("Message", h("textarea", {className: "qc-message-input", rows: 5, maxLength: 64000, value: text, disabled: busy, placeholder: "Your message… Discord Markdown is supported.", onChange: e => editMessage(e.target.value)})),
                code("AES-256-GCM(K, nonce, message) → ciphertext + tag"),
                p("One attachment carries u, v, and the encrypted message. Your saved m reopens sent files; the recipient uses their private key."),
                h("span", {className: "qc-muted"}, "AES-GCM is Qcord's message layer. ML-KEM follows FIPS 203.")),
            h(R.Fragment, null, h("div", {className: "qc-label-row"}, h("strong", null, "Attachment preview"), h("small", {className: "qc-muted"}, `${Buffer.byteLength(draft.wire).toLocaleString()} bytes`)), h("pre", {className: "qc-json", tabIndex: 0, "aria-label": "Exact attachment JSON"}, draft.wire)));
        }
        if (stopped) return h("div", {className: "qc-panel"}, p("Qcord is stopped. Enable it and reopen the panel."));
        return h("div", {className: "qc-panel qc-composer"},
            h("header", {className: "qc-toolbar"},
                button(h(R.Fragment, null, profile && h(Avatar, {profile}), h("span", null, h("strong", null, profile?.displayName || "Choose recipient"), h("small", null, row ? "Public key saved" : "Save their public key"))), () => setContactsTab("contacts"), {className: "qc-recipient", "aria-label": "Choose recipient"}),
                h("div", {className: "qc-mode-controls"}, h(Switch, {label: "Auto encrypt", checked: autoEncrypt, disabled: !plugin.sendHookReady, title: plugin.sendHookReady ? "Turn normal chat text into a reviewed .qcord attachment" : "Unavailable in this Discord build", onChange: value => run(async () => plugin.setAutomatic("encrypt", value))}),
                    h(Switch, {label: "Auto decrypt", checked: autoDecrypt, onChange: value => run(async () => plugin.setAutomatic("decrypt", value))})),
                button(h(R.Fragment, null, h(Icon, {name: "keys"}), "Your keys"), () => setContactsTab("keys"), {className: "qc-panel-button", "aria-label": "Your keys"}),
                button(h(R.Fragment, null, h(Icon, {name: "contacts"}), "Contacts"), () => setContactsTab("contacts"), {className: "qc-panel-button", "aria-label": "Contacts"}),
                onClose && button("Exit", onClose, {className: "qc-exit", "aria-label": "Exit Qcord", title: "Exit Qcord and return to chat"})),
            h(Tabs, {label: "Encapsulation steps", items: stages.map((name, i) => [i, `${i + 1}. ${name}`]), value: step, onChange: navigate, disabled: busy}),
            h("main", {className: "qc-main", role: "tabpanel", "aria-label": `${stages[step]} stage`, "aria-busy": busy}, content),
            h("footer", {className: "qc-footer"}, button("Previous step", () => navigate(step - 1), {disabled: busy || step === 0}),
                h("div", {className: "qc-feedback"}, h("div", {role: "alert", className: "qc-error"}, error), h("div", {role: "status"}, busy ? "Working…" : notice)),
                button(h(R.Fragment, null, h(Icon, {name: "upload"}), "Open file"), () => filePicker.current.click(), {className: "qc-quiet qc-open-file", title: "Decrypt a downloaded .qcord file on this device", disabled: busy}),
                h("input", {ref: filePicker, hidden: true, type: "file", accept: ".qcord,application/json", "aria-label": "Open saved .qcord file", onChange: e => {
                    const file = e.target.files?.[0]; e.target.value = "";
                    if (file) run(async () => { if (file.size > MAX_DECODED_FILE_SIZE) throw new Error("Qcord file is too large."); const result = await plugin.openFile(await file.text(), channel); if (alive.current) setOpened(result); });
                }}),
                step < 3 ? button("Next", () => navigate(step + 1), {className: "qc-primary", disabled: busy || !row}) : button(attached ? "Attached" : "Attach .qcord", () => run(async () => { await plugin.stageDraft(draft); if (alive.current) { setAttached(true); setNotice("Ready in Discord. Press Send to share."); } }), {className: "qc-primary", disabled: busy || attached || !draft || !messageReady})),
            opened && h(OpenedMessage, {result: opened, onDismiss: () => setOpened(null)}),
            contactsTab && h(Contacts, {key: contactsTab, plugin, channel, keys, view: contactsTab, onClose: () => setContactsTab(null), onChanged: refreshed, onSelect: id => { invalidate(); setChannel(id); setPartners(plugin.getSavedPartners()); setStep(0); }}));
    }
    return h(Panel);
};
