"use strict";

const {PQC} = require("./pqc");
const {sha3_256, sha3_512} = require("@noble/hashes/sha3.js");
const {ACTIVE_SCHEME} = require("./constants");
const {PARAMETER_SETS, parameters} = require("./parameters");
const M = require("./mlkem");
const createUI = require("./ui");
const createContacts = require("./contacts");
const hex = bytes => Buffer.from(bytes).toString("hex");
const stages = ["Recipient key", "Derive K", "Construct u, v", "Attach"];

module.exports = function getSettingsPanel(plugin, {onClose} = {}) {
    const R = BdApi.React, ui = createUI(R);
    const {h, p, button, field, formula, code, Tabs, Avatar, Polynomial} = ui;
    const Contacts = createContacts(R, ui);
    const split = (left, right) => h("div", {className: "qc-split"}, h("section", {className: "qc-explanation"}, left), h("section", {className: "qc-visual"}, right));

    function Panel() {
        const [step, setStep] = R.useState(0), [scheme, setScheme] = R.useState(plugin.scheme || ACTIVE_SCHEME);
        const [channel, setChannel] = R.useState(() => plugin.currentChannel() || "");
        const [partners, setPartners] = R.useState(() => plugin.getSavedPartners());
        const [keys, setKeys] = R.useState(null), [draft, setDraft] = R.useState(null);
        const [busy, setBusy] = R.useState(false), [error, setError] = R.useState(""), [notice, setNotice] = R.useState("");
        const [contactsOpen, setContactsOpen] = R.useState(false), [attached, setAttached] = R.useState(false), [stopped, setStopped] = R.useState(!plugin.running);
        const [keyTab, setKeyTab] = R.useState("shape"), [part, setPart] = R.useState("u");
        const [vectorIndex, setVectorIndex] = R.useState(0), [matrixCell, setMatrixCell] = R.useState(0), [coefficient, setCoefficient] = R.useState(0);
        const alive = R.useRef(true), ticket = R.useRef(0), pending = R.useRef(false), preview = R.useRef(null);
        const params = parameters(scheme), indices = Array.from({length: params.k}, (_, i) => i);
        const row = partners.find(r => r.channel_id === channel && r.key_algorithm === scheme);
        const anyRow = partners.find(r => r.channel_id === channel);
        const profile = anyRow ? plugin.getPartnerProfile(anyRow.user_id) : null;
        const publicInfo = R.useMemo(() => row ? M.publicTrace(PQC.createPublicKey(row.public_encaps).bytes, scheme) : null, [row, scheme]);
        R.useEffect(() => {
            const stop = () => { alive.current = false; ticket.current++; M.wipe(preview.current); setDraft(null); setKeys(null); setStopped(true); };
            plugin.panels.add(stop);
            return () => { alive.current = false; ticket.current++; M.wipe(preview.current); plugin.panels.delete(stop); };
        }, []);
        R.useEffect(() => {
            let active = true; setKeys(null);
            plugin.generateKeys(scheme).then(value => { if (active && alive.current) setKeys(value); }).catch(e => { if (active && alive.current) setError(e.message); });
            return () => { active = false; };
        }, [scheme, partners]);
        function invalidate() {
            ticket.current++; M.wipe(preview.current); preview.current = null; setDraft(null); setAttached(false); setError(""); setNotice("");
        }
        function changeScheme(value) {
            invalidate(); plugin.setScheme(value); setScheme(value); setVectorIndex(0); setMatrixCell(0); setStep(0);
        }
        async function run(task) {
            if (pending.current || !alive.current || !plugin.running) return;
            pending.current = true; setBusy(true); setError(""); setNotice("");
            try { await task(); } catch (e) { if (alive.current) setError(e.message); }
            finally { pending.current = false; if (alive.current) setBusy(false); }
        }
        async function prepare(target, fresh = false) {
            if (!row) throw new Error(`Choose a recipient with a saved ${params.label} public key.`);
            if (draft && !fresh) { setStep(target); return; }
            invalidate();
            const request = ++ticket.current;
            const result = await plugin.prepareEncapsulation(channel, scheme);
            if (!alive.current || request !== ticket.current) { M.wipe(result); return; }
            preview.current = result; setDraft(result); setStep(target);
        }
        const navigate = value => run(async () => { if (value >= 1) await prepare(value); else setStep(value); });
        const refreshed = detected => { invalidate(); setPartners(plugin.getSavedPartners()); if (detected) changeScheme(detected); };
        const vectorSelector = field("Vector index", h("select", {value: vectorIndex, onChange: e => setVectorIndex(Number(e.target.value))}, indices.map(i => h("option", {key: i, value: i}, i))));
        let content;
        if (step === 0) {
            content = split(h(R.Fragment, null,
                h("h3", null, "Unpack the recipient's public_encaps"),
                p("Start with the key your recipient shared. Its decoded byte length identifies the ML-KEM parameter set."),
                formula(`ek = ByteEncode₁₂(t̂) ∥ ρ`),
                formula(`${params.publicBytes} = 384 × ${params.k} + 32 bytes`),
                h("table", {className: "qc-parameters"}, h("thead", null, h("tr", null, ["Set", "ek bytes", "t̂", "Â"].map(s => h("th", {key: s}, s)))),
                    h("tbody", null, Object.entries(PARAMETER_SETS).map(([s, v]) => h("tr", {key: s, "data-selected": s === scheme}, h("td", null, v.label), h("td", null, v.publicBytes), h("td", null, `${v.k} × 1`), h("td", null, `${v.k} × ${v.k}`))))),
                p("Every polynomial has 256 coefficients modulo 3329. 512, 768 and 1024 name parameter sets; their NIST security categories are 1, 3 and 5."),
                p("The matrix is reconstructed from ρ, not sent as a full matrix in the key.")),
            !publicInfo ? h("div", {className: "qc-empty-state"}, p("Save the public key supplied by your recipient."), button("Contacts & keys", () => setContactsOpen(true))) :
            h(R.Fragment, null, h(Tabs, {label: "Public key views", items: [["shape", "Dimensions"], ["matrix", "Matrix Â"], ["vector", "Vector t̂"], ["saved", "Saved public_encaps"]], value: keyTab, onChange: setKeyTab}),
                keyTab === "shape" ? h(R.Fragment, null,
                    h("h3", null, `${params.label} detected · ${params.publicBytes} raw bytes`),
                    h("div", {className: "qc-packet-bars"}, h("span", null, `Encoded t̂ · ${384 * params.k} bytes`), h("span", null, "ρ · 32 bytes")),
                    h("div", {className: "qc-key-shapes"}, h("div", null, p(`Â: ${params.k} × ${params.k} polynomials`), h("div", {className: "qc-matrix", "aria-label": "Matrix dimensions", style: {gridTemplateColumns: `repeat(${params.k}, 1fr)`}}, indices.flatMap(i => indices.map(j => h("span", {key: `${i}-${j}`}, `Â[${i},${j}]`))))),
                        h("div", null, p(`t̂: ${params.k} polynomials`), h("div", {className: "qc-matrix", "aria-label": "Vector dimensions"}, indices.map(i => h("span", {key: i}, `t̂[${i}]`))))),
                    code(`ρ = ${hex(publicInfo.rho)}`), p("Hats indicate NTT representation. A and t are the same public objects expressed as coefficient polynomials.")) :
                keyTab === "matrix" ? h(R.Fragment, null,
                    h("div", {className: "qc-matrix", style: {gridTemplateColumns: `repeat(${params.k}, 1fr)`}, "aria-label": "Public matrix A hat"}, indices.flatMap(i => indices.map(j => button(`Â[${i},${j}]`, () => setMatrixCell(i * params.k + j), {key: `${i}-${j}`, "aria-pressed": matrixCell === i * params.k + j})))),
                    h(Polynomial, {values: publicInfo.aHat[Math.floor(matrixCell / params.k)][matrixCell % params.k], name: "Selected Â polynomial · NTT"}),
                    code("Â[i,j] = SampleNTT(ρ ∥ byte(j) ∥ byte(i))")) :
                keyTab === "vector" ? h(R.Fragment, null, vectorSelector, h(Polynomial, {values: publicInfo.tHat[vectorIndex], name: `t̂[${vectorIndex}] · NTT`})) :
                h(R.Fragment, null, field("Saved public_encaps", h("textarea", {readOnly: true, rows: 7, value: row.public_encaps})), p(`Base64 decodes to ${params.publicBytes} raw bytes. The config stores this key once per recipient and parameter set.`))));
        }
        if (step === 1 && draft) {
            const digest = sha3_256(PQC.createPublicKey(draft.public_encaps).bytes);
            const kr = sha3_512(Uint8Array.from([...draft.trace.m, ...digest]));
            const kHex = hex(kr.slice(0, 32)), rHex = hex(kr.slice(32)); kr.fill(0);
            content = split(h(R.Fragment, null,
                h("h3", null, "Sample m, then derive K and r"),
                p("The sender samples a fresh random 32-byte m for this recipient's encapsulation."),
                formula("(K, r) = G(m ∥ H(ek))"),
                formula("H = SHA3-256; G = SHA3-512"),
                p("H hashes the whole raw public key. G returns 64 bytes: the first 32 are K, the last 32 are the encryption seed r."),
                p("FIPS 203 calls the ephemeral noise vector y. If your course calls it r⃗, that vector is distinct from the 32-byte seed r."),
                button("Sample fresh m", () => run(() => prepare(1, true)), {disabled: busy})),
            h(R.Fragment, null, code(`m (32 bytes, local secret)\n${hex(draft.trace.m)}`), code(`K = G(m ∥ H(ek))[0:32]\n${kHex}`), code(`r = G(m ∥ H(ek))[32:64]\n${rHex}`),
                formula("μ = Decompress₁(ByteDecode₁(m))"), h(Polynomial, {values: draft.trace.mu, name: "μ · bit 0 → 0, bit 1 → 1665"}),
                p("m is retained locally when you attach. A new draft always samples fresh m; saved m reproduces only its original K and ciphertext.")));
        }
        if (step === 2 && draft) {
            const t = draft.trace, i = vectorIndex, j = coefficient;
            const values = part === "u" ? t.u[i] : t.v;
            const product = part === "u" ? M.mod(values[j] - t.e1[i][j]) : M.mod(values[j] - t.e2[j] - t.mu[j]);
            content = split(h(R.Fragment, null, h("h3", null, "Construct the ciphertext pair"),
                formula("u = Aᵀy + e₁"), formula("v = tᵀy + μ + e₂"),
                p("These are polynomial products and sums modulo 3329 in Rq = ℤq[X]/(X²⁵⁶ + 1). In row-vector notation: uᵀ = yᵀA + e₁ᵀ, as in your course's rA + e₁."),
                code("u = NTT⁻¹(Âᵀ ∘ ŷ) + e₁\nv = NTT⁻¹(t̂ᵀ ∘ ŷ) + μ + e₂"),
                p(`Sample y from CBDη₁ (η₁=${params.eta1}); e₁ and e₂ from CBDη₂ (η₂=${params.eta2}), using PRF(r, N) with successive nonces N=0…${2 * params.k}.`),
                h("details", null, h("summary", null, "See sampled noise"), code(`y[${i}] first 16: ${t.rVector[i].slice(0, 16).join(", ")}\ne₁[${i}] first 16: ${t.e1[i].slice(0, 16).join(", ")}\ne₂ first 16: ${t.e2.slice(0, 16).join(", ")}`)),
                p("The independently reconstructed, compressed ciphertext matches the bundled ML-KEM implementation byte for byte.")),
            h(R.Fragment, null, h(Tabs, {label: "Ciphertext components", items: [["u", "Compute u"], ["v", "Compute v"]], value: part, onChange: setPart}),
                part === "u" ? vectorSelector : p("v is one polynomial, with 256 coefficients."),
                h(Polynomial, {values, name: part === "u" ? `u[${i}] · before compression` : "v · before compression"}),
                field("Construction coefficient", h("input", {type: "range", min: 0, max: 255, value: j, onChange: e => setCoefficient(Number(e.target.value))})),
                code(part === "u" ? `u[${i}][${j}] = (${product} + ${t.e1[i][j]}) mod 3329 = ${values[j]}` : `v[${j}] = (${product} + ${t.mu[j]} + ${t.e2[j]}) mod 3329 = ${values[j]}`),
                formula(`Compress${part === "u" ? params.du : params.dv}(${values[j]}) = ${M.compress(values[j], part === "u" ? params.du : params.dv)}`),
                p("The file's u and v arrays hold compressed coefficients. Uncompressed values remain in this local draft.")));
        }
        if (step === 3 && draft) {
            content = split(h(R.Fragment, null, h("h3", null, "Send one encapsulation to the recipient"),
                formula("c = ByteEncode(u) ∥ ByteEncode(v)"),
                p(`The JSON stores ${params.k} compressed u polynomials at ${params.du} bits per coefficient and one v polynomial at ${params.dv} bits. Packing them reconstructs the ${params.ciphertextBytes}-byte FIPS 203 ciphertext exactly.`),
                code(`.qcord: qcord_version, parameter_set, u, v\nLocal config: recipient public_encaps + each encapsulation's m`),
                p("The recipient uses their private dk and c to obtain K through ML-KEM.Decaps. The sender can reproduce K from saved m and the saved recipient public key."),
                p("The config contains private material, including m; keep it local. m retention is for this course walkthrough, outside the standard's ephemeral-randomness lifecycle."),
                p("Decapsulation returns a key even for a modified ciphertext or a different recipient. ML-KEM does not provide a public success flag or sender authentication.")),
            h(R.Fragment, null, h("h3", null, "Exact .qcord attachment"), h("pre", {className: "qc-json"}, draft.wire)));
        }
        if (stopped) return h("div", {className: "qc-panel"}, h("h2", null, "Qcord is stopped"), p("Enable the plugin and reopen the panel."));
        return h("div", {className: "qc-panel qc-composer"},
            h("header", {className: "qc-header"}, h("div", null, h("span", {className: "qc-eyebrow"}, "QCORD / FIPS 203"), h("h2", null, "From recipient key to u, v")),
                h("div", {className: "qc-row"}, field("Open .qcord locally", h("input", {type: "file", accept: ".qcord,application/json", disabled: busy, onChange: e => {
                    const file = e.target.files?.[0]; e.target.value = "";
                    if (file) run(async () => { if (file.size > 1024 * 1024) throw new Error("Qcord file is too large."); const result = await plugin.openFile(await file.text(), channel); if (alive.current) setNotice(`${result.source} · ${result.scheme.toUpperCase()} · K (local): ${result.key}. This does not authenticate the sender. Recipient decapsulation does not confirm ciphertext validity.`); });
                }})), onClose && button("Close", onClose))),
            h("div", {className: "qc-toolbar"}, field("ML-KEM parameter set", h("select", {value: scheme, disabled: busy, onChange: e => changeScheme(e.target.value)}, Object.entries(PARAMETER_SETS).map(([s, v]) => h("option", {key: s, value: s}, v.label)))),
                h("div", {className: "qc-level"}, h("span", null, "NIST category"), h("strong", null, params.category)),
                button(h(R.Fragment, null, profile && h(Avatar, {profile}), h("span", null, h("strong", null, profile?.displayName || "Choose a recipient"), h("small", null, row ? `${params.publicBytes} bytes · ${params.label}` : "Public key needed"))), () => setContactsOpen(true), {className: "qc-recipient", disabled: busy, "aria-label": "Choose recipient"}),
                button("Contacts & keys", () => setContactsOpen(true), {disabled: busy})),
            h(Tabs, {label: "Encapsulation steps", items: stages.map((name, i) => [i, `${i + 1}. ${name}`]), value: step, onChange: navigate, disabled: busy}),
            h("main", {className: "qc-main", role: "tabpanel", "aria-label": `${stages[step]} stage`, "aria-busy": busy}, content),
            h("aside", {className: "qc-source"}, "FIPS 203 · Algorithms 14, 17, 20, 21 · Tables 2, 3 · Course tool; not a FIPS-validated module."),
            h("div", {className: "qc-feedback"}, h("div", {role: "alert", className: "qc-error"}, error), h("div", {role: "status"}, busy ? "Working locally…" : notice)),
            h("footer", {className: "qc-footer"}, button("Back", () => navigate(step - 1), {disabled: busy || step === 0}), h("span", {className: "qc-muted"}, `Step ${step + 1} of 4 · ${params.label}`),
                step < 3 ? button("Next", () => navigate(step + 1), {className: "qc-primary", disabled: busy || !row}) : button(attached ? "Attached" : "Attach .qcord to composer", () => run(async () => { await plugin.stageDraft(draft); if (alive.current) { setAttached(true); setNotice("m saved locally. Review the attachment in Discord and press Send."); } }), {className: "qc-primary", disabled: busy || attached || !draft})),
            contactsOpen && h(Contacts, {plugin, scheme, channel, keys, onClose: () => setContactsOpen(false), onChanged: refreshed, onSelect: id => { invalidate(); setChannel(id); setPartners(plugin.getSavedPartners()); }}));
    }
    return h(Panel);
};
