"use strict";

const {PQC} = require("./pqc");
const {ACTIVE_SCHEME} = require("./constants");
const {PARAMETER_SETS, parameters} = require("./parameters");
const L = require("./learning");
const createUI = require("./ui");
const createContacts = require("./contacts");
const hex = bytes => Buffer.from(bytes).toString("hex");
const stageNames = ["Write", "Encode", "Keys", "Encapsulate", "Attach"];

module.exports = function getSettingsPanel(plugin, {onClose} = {}) {
    const R = BdApi.React, ui = createUI(R);
    const {h, p, button, field, formula, code, Tabs, Avatar, Polynomial} = ui;
    const Contacts = createContacts(R, ui);
    const split = (left, right) => h("div", {className: "qc-split"}, h("section", {className: "qc-explanation"}, left), h("section", {className: "qc-visual"}, right));
    const subscript = n => String(n).replace(/\d/g, d => "₀₁₂₃₄₅₆₇₈₉"[Number(d)]);

    function Compression({params}) {
        const [x, setX] = R.useState(1665), [d, setD] = R.useState(1);
        const compressed = L.compress(x, d), restored = L.decompress(compressed, d);
        return h(R.Fragment, null,
            field(`Exercise coefficient x = ${x}`, h("input", {type: "range", min: 0, max: 3328, value: x, onChange: e => setX(Number(e.target.value))})),
            field("Bits d", h("select", {value: d, onChange: e => setD(Number(e.target.value))}, [1, params.dv, params.du].map(n => h("option", {key: n, value: n}, n)))),
            formula(`Compress${subscript(d)}(${x}) = round(${2**d} × ${x} / 3329) mod ${2**d} = ${compressed}`),
            formula(`Decompress${subscript(d)}(${compressed}) = round(3329 × ${compressed} / ${2**d}) = ${restored}`),
            p("Exercise values update live. They do not change your keys or attachment."));
    }

    function Panel() {
        const [step, setStep] = R.useState(0), [enabled, setEnabled] = R.useState(plugin.enabled);
        const [scheme, setScheme] = R.useState(plugin.scheme || ACTIVE_SCHEME);
        const [text, setText] = R.useState(() => plugin.composerText());
        const [channel, setChannel] = R.useState(() => plugin.currentChannel() || "");
        const [partners, setPartners] = R.useState(() => plugin.getSavedPartners());
        const [keys, setKeys] = R.useState(null), [draft, setDraft] = R.useState(null);
        const [busy, setBusy] = R.useState(false), [error, setError] = R.useState(""), [notice, setNotice] = R.useState("");
        const [contactsOpen, setContactsOpen] = R.useState(false), [attached, setAttached] = R.useState(false), [stopped, setStopped] = R.useState(!plugin.running);
        const [encodeTab, setEncodeTab] = R.useState("bytes"), [keyTab, setKeyTab] = R.useState("matrix"), [kemTab, setKemTab] = R.useState("mu"), [reviewTab, setReviewTab] = R.useState("summary");
        const [vectorIndex, setVectorIndex] = R.useState(0), [matrixCell, setMatrixCell] = R.useState(0), [bytePage, setBytePage] = R.useState(0), [noise, setNoise] = R.useState("r");
        const [privateView, setPrivateView] = R.useState(null), [privateVariable, setPrivateVariable] = R.useState("s");
        const [revision, setRevision] = R.useState(0);
        const alive = R.useRef(true), ticket = R.useRef(0), pending = R.useRef(false), preview = R.useRef(null), secret = R.useRef(null);
        const params = parameters(scheme), indices = Array.from({length: params.k}, (_, i) => i);
        const row = partners.find(r => r.channel_id === channel && r.key_algorithm === scheme);
        const anyRow = partners.find(r => r.channel_id === channel);
        const profile = anyRow ? plugin.getPartnerProfile(anyRow.user_id) : null;
        const publicInfo = R.useMemo(() => {
            try { return row ? L.publicTrace(PQC.createPublicKey(row.public_key_spki_base64).bytes, scheme) : null; } catch { return null; }
        }, [row, scheme]);
        R.useEffect(() => {
            const stop = () => { alive.current = false; ticket.current++; L.wipe(preview.current); L.wipe(secret.current); setDraft(null); setPrivateView(null); setKeys(null); setText(""); setStopped(true); };
            plugin.panels.add(stop);
            return () => { alive.current = false; ticket.current++; L.wipe(preview.current); L.wipe(secret.current); plugin.panels.delete(stop); };
        }, []);
        R.useEffect(() => {
            let active = true; setKeys(null);
            plugin.generateKeys(scheme).then(value => { if (active && alive.current) setKeys(value); }).catch(e => { if (active && alive.current) setError(e.message); });
            return () => { active = false; };
        }, [scheme, revision]);
        function invalidate() {
            ticket.current++; L.wipe(preview.current); preview.current = null; setDraft(null); setAttached(false); setError(""); setNotice("");
        }
        function clearPrivate() { L.wipe(secret.current); secret.current = null; setPrivateView(null); }
        function changeScheme(value) {
            invalidate(); clearPrivate(); plugin.setScheme(value); setScheme(value); setKeys(null); setVectorIndex(0); setMatrixCell(0); setStep(Math.min(step, 2));
        }
        async function run(task) {
            if (pending.current || !alive.current || !plugin.running) return;
            pending.current = true; setBusy(true); setError(""); setNotice("");
            try { await task(); } catch (e) { if (alive.current) setError(e.message); }
            finally { pending.current = false; if (alive.current) setBusy(false); }
        }
        async function prepare(target, fresh = false) {
            if (!row) throw new Error(`Choose a contact with a saved ${params.label} public key.`);
            if (!text.length) throw new Error("Write a message first.");
            if (draft && !fresh) { setStep(target); return; }
            if (fresh) invalidate();
            const request = ++ticket.current;
            const result = await plugin.encryptMessage(channel, text, {inspect: true, scheme});
            if (!alive.current || request !== ticket.current) { L.wipe(result); return; }
            preview.current = result; setDraft(result); setStep(target);
        }
        const navigate = value => run(async () => { if (value >= 3) await prepare(value); else setStep(value); });
        const editText = value => { invalidate(); setText(value); setBytePage(0); };
        const refreshed = () => { invalidate(); clearPrivate(); setPartners(plugin.getSavedPartners()); setRevision(v => v + 1); };
        const bytes = new TextEncoder().encode(text), block = bytes.slice(bytePage*32, bytePage*32+32);
        const hasBOM = bytes.length >= 3 && bytes[0] === 239 && bytes[1] === 187 && bytes[2] === 191;
        const vectorSelector = field("Vector index", h("select", {value: vectorIndex, onChange: e => setVectorIndex(Number(e.target.value))}, indices.map(i => h("option", {key: i, value: i}, i))));
        let content, pages, detail;

        if (step === 0) {
            pages = "32–35, 56, 97";
            content = split(h(R.Fragment, null,
                h("h3", null, "Start with your words"),
                field("Your message · stays local until you send", h("textarea", {className: "qc-message", rows: 6, maxLength: 64000, value: text, disabled: busy, onChange: e => editText(e.target.value), placeholder: "Write a message…"})),
                h("div", {className: "qc-row"}, h("span", {className: "qc-muted"}, `${bytes.length} UTF-8 bytes${hasBOM ? " · leading BOM detected" : ""}`), button("Read Discord draft", () => editText(plugin.composerText()), {disabled: busy})),
                p("Next shows your bytes and bits. Use the tabs to revisit any step.")),
            h(R.Fragment, null, h("h3", null, "One message. Two ways to compose."),
                h("div", {className: "qc-option"}, h("h4", null, "Walk through the math"), p("Follow your text, the recipient's public key, and the actual polynomial values into the attachment.")),
                h("div", {className: "qc-option"}, h("h4", null, "Prepare it automatically"), p("Skip the lesson and review the encrypted file. With Quantum conversations on, pressing Enter in Discord also stages a file."),
                    button("Make .qcord automatically", () => run(() => prepare(4)), {disabled: busy || !row || !text, className: "qc-primary"})),
                h("div", {className: "qc-facts"}, code(`n = 256   q = 3329   k = ${params.k}`), code(`ek ${params.publicBytes} B · dk ${params.privateBytes} B · c ${params.ciphertextBytes} B`)),
                !row && h("div", {className: "qc-note"}, `Open Contacts & keys to save a ${params.label} recipient key.`)));
        }
        if (step === 1) {
            pages = "10, 57–59, 65–68, 86, 97";
            content = split(h(R.Fragment, null, h("h3", null, "Text becomes bytes, then bits"),
                field("Edit your message", h("textarea", {rows: 3, value: text, maxLength: 64000, onChange: e => editText(e.target.value)})),
                p("UTF-8 encodes your characters. BytesToBits below reads the least-significant bit first, matching the slides."),
                formula("μᵢ = Decompress₁(bᵢ)"), formula("0 → 0     1 → 1665"),
                h("div", {className: "qc-note"}, "Text mapping is an exercise. Actual ML-KEM uses a random 32-byte m; your complete text goes to AES-GCM.")),
            h(R.Fragment, null, h(Tabs, {label: "Encoding views", items: [["bytes", "Bytes & bits"], ["polynomial", "Polynomial"], ["bom", "UTF-8 BOM"]], value: encodeTab, onChange: setEncodeTab}),
                encodeTab === "bytes" && h("div", {className: "qc-byte-grid"}, Array.from(block).map((b,i) => h("div", {key:i,className:hasBOM && bytePage===0 && i<3 ? "qc-bom-byte" : ""}, h("small", null, `byte ${bytePage*32+i}`), h("strong", null, b), code(L.bits([b]).join(""))))),
                encodeTab === "polynomial" && h(Polynomial, {values: L.bits(block).map(b => L.decompress(b,1)), name: "Text mapping exercise μ"}),
                encodeTab === "bom" && h("div", {className: "qc-bom-view"}, h("h3", null, hasBOM ? "Leading BOM detected and preserved" : "No leading BOM in this message"),
                    formula("U+FEFF → EF BB BF"), p("BOM means Byte Order Mark. In UTF-8 it can mark the start of a text stream; UTF-8 has no byte-order choice."),
                    p("If pasted text starts with U+FEFF, Qcord encrypts and recovers it unchanged. The byte preview highlights its three bytes."),
                    p("Generated .qcord JSON and plugin source use UTF-8 without an added BOM. An optional BOM on an imported JSON file is accepted.")),
                encodeTab !== "bom" && h("div", {className: "qc-row qc-pagination"}, button("Previous 32 bytes", () => setBytePage(bytePage-1), {disabled: bytePage===0}), h("span", null, `${bytes.length ? bytePage*32+1 : 0}–${Math.min(bytes.length,(bytePage+1)*32)} / ${bytes.length} bytes`), button("Next 32 bytes", () => setBytePage(bytePage+1), {disabled: (bytePage+1)*32>=bytes.length}))));
        }
        if (step === 2) {
            pages = "34, 56, 64, 72–75, 82, 96";
            detail = "Final FIPS 203: (ρ, σ) = G(d ∥ byte(k)); Â[i,j] = SampleNTT(ρ ∥ byte(j) ∥ byte(i)). Slide 74 uses older details.";
            content = split(h(R.Fragment, null, h("h3", null, "A public key built from polynomials"),
                p(`${params.label} uses a ${params.k} × ${params.k} matrix Â. Each square is a polynomial with 256 coefficients modulo 3329.`),
                formula("t̂ = Â ∘ ŝ + ê"), formula("ek = ByteEncode₁₂(t̂) ∥ ρ"),
                p("A hat marks an NTT representation. The ∘ operation multiplies polynomials in that representation."),
                h("div", {className: "qc-facts"}, code(`k = ${params.k} · η₁ = ${params.eta1} · η₂ = ${params.eta2}`)),
                p("Your contact keeps s and e private. Only your own saved secret vectors can be revealed here.")),
            h(R.Fragment, null, h(Tabs, {label: "Key views", items: [["matrix", "Public matrix"], ["vector", "Public vector"], ["secret", "My secret"], ["format", "Key format"]], value: keyTab, onChange: setKeyTab}),
                !publicInfo && keyTab !== "secret" && keyTab !== "format" ? h("div", {className: "qc-empty-state"}, p(`Select a contact with a ${params.label} public key.`), button("Choose contact", () => setContactsOpen(true))) :
                keyTab === "matrix" ? h(R.Fragment, null,
                    h("div", {className: "qc-matrix", style: {gridTemplateColumns: `repeat(${params.k}, 1fr)`}, "aria-label": "Public matrix A hat"}, publicInfo.aHat.flatMap((r,i) => r.map((_,j) => button(`Â[${i}, ${j}]`, () => setMatrixCell(i*params.k+j), {key:i*params.k+j,"aria-pressed":matrixCell===i*params.k+j})))),
                    h(Polynomial, {values: publicInfo.aHat[Math.floor(matrixCell/params.k)][matrixCell%params.k], name: `Â[${Math.floor(matrixCell/params.k)}, ${matrixCell%params.k}] · NTT`})) :
                keyTab === "vector" ? h(R.Fragment, null, vectorSelector, h(Polynomial, {values: publicInfo.tHat[vectorIndex], name: `t̂[${vectorIndex}] · NTT`}), code(`ρ = ${hex(publicInfo.rho)}`)) :
                keyTab === "secret" ? h(R.Fragment, null,
                    button(privateView ? "Hide my secret vectors" : "Reveal my local s and e", () => {
                        if (privateView) clearPrivate();
                        else if (keys) { const value=L.privateTrace(keys.publicKey.bytes,keys.privateKey.bytes,scheme); secret.current=value; setPrivateView(value); }
                    }, {disabled: !keys}),
                    privateView ? h(R.Fragment, null, h("div", {className: "qc-row"}, vectorSelector, field("Private vector", h("select", {value:privateVariable,onChange:e=>setPrivateVariable(e.target.value)}, h("option",{value:"s"},"Secret s"),h("option",{value:"e"},"Noise e")))),
                        h(Polynomial, {values:privateView[privateVariable][vectorIndex],name:`My ${privateVariable}[${vectorIndex}]`,signed:true}), p("Private values from your own saved key. Do not share screenshots.")) : p("Reveal is optional. Your contact's secret values are never available here.")) :
                h(R.Fragment, null, h("h3", null, "Public and private parts"), formula("dk = dkPKE ∥ ek ∥ H(ek) ∥ z"), code(`ek: ${params.publicBytes} bytes\ndk: ${params.privateBytes} bytes\nShared secret K: 32 bytes`), p("ρ reconstructs the public matrix. z is a private fallback used when decapsulation implicitly rejects a ciphertext."), button("Open Contacts & keys", () => setContactsOpen(true)))));
        }
        if (step === 3 && draft) {
            pages = "53–60, 84–90, 97";
            detail = "Scalar r is a 32-byte seed; r⃗ is a vector of noise polynomials. H = SHA3-256; G = SHA3-512. This trace matches the actual library ciphertext.";
            const t = draft.trace;
            const vector = kemTab === "noise" ? noise === "r" ? t.rVector[vectorIndex] : noise === "e1" ? t.e1[vectorIndex] : t.e2 : kemTab === "u" ? t.u[vectorIndex] : kemTab === "v" ? t.v : t.mu;
            const label = kemTab === "noise" ? `${noise}[${noise === "e2" ? "" : vectorIndex}]` : kemTab === "u" ? `u[${vectorIndex}]` : kemTab === "v" ? "v" : "μ · random m";
            content = split(h(R.Fragment, null, h("h3", null, "Encapsulate for your contact"),
                formula("(K, r) = G(m ∥ H(ek))"),
                kemTab === "u" ? formula("u = NTT⁻¹(Âᵀ ∘ r̂) + e₁") : kemTab === "v" ? formula("v = NTT⁻¹(t̂ᵀ ∘ r̂) + e₂ + μ") : kemTab === "compress" ? formula(`c = Encode${subscript(params.du)}(Compress${subscript(params.du)}(u)) ∥ Encode${subscript(params.dv)}(Compress${subscript(params.dv)}(v))`) : formula("μ = Decompress₁(ByteDecode₁(m))"),
                p("These are real values from the selected recipient's envelope. Fresh randomness changes them while your text stays the same."),
                h("div", {className: "qc-packet-bars"}, h("span", null, `c₁ · ${32*params.du*params.k} B`), h("span", null, `c₂ · ${32*params.dv} B`)),
                code(`c: first 16 / ${params.ciphertextBytes} bytes\n${hex(t.ciphertext.slice(0,16))}`),
                button("Sample fresh randomness", () => run(() => prepare(3,true)), {disabled: busy})),
            h(R.Fragment, null, h(Tabs, {label: "Encapsulation views", items: [["mu", "Encode m"], ["noise", "Noise"], ["u", "Compute u"], ["v", "Compute v"], ["compress", "Compress"]], value: kemTab, onChange: setKemTab}),
                kemTab === "compress" ? h(Compression, {params, key:scheme}) : h(R.Fragment, null,
                    (kemTab === "noise" || kemTab === "u") && h("div", {className: "qc-row"}, vectorSelector, kemTab === "noise" && field("Noise vector", h("select", {value:noise,onChange:e=>setNoise(e.target.value)}, h("option",{value:"r"},"r⃗"),h("option",{value:"e1"},"e₁"),h("option",{value:"e2"},"e₂")))),
                    h(Polynomial, {values:vector,name:label,signed:kemTab==="noise"}),
                    kemTab === "mu" && p("m is uniformly random, not your typed text. Each 1 bit becomes a coefficient of 1665."))));
        }
        if (step === 4 && draft) {
            pages = "35, 91–93, 97–98";
            detail = "HKDF-SHA256 and AES-256-GCM are Qcord's application layer. FIPS 204/205 signatures and PKI are deferred.";
            content = split(h(R.Fragment, null, h("h3", null, "Review before attaching"),
                h("div", {className: "qc-success"}, "Local decryption passed · exact UTF-8 text recovered"),
                p("A fresh AES key encrypts your text. Each participant's ML-KEM shared secret derives a wrapping key for that AES key."),
                h("dl", {className: "qc-stats"}, h("dt",null,"Recipient"),h("dd",null,profile?.username || channel),h("dt",null,"Parameter set"),h("dd",null,params.label),h("dt",null,"File"),h("dd",null,`${Buffer.byteLength(draft.wire)} bytes`),h("dt",null,"KEM ciphertext"),h("dd",null,`${params.ciphertextBytes} bytes / envelope`)),
                p("The file includes your envelope too, so your saved dk can read your sent message."),
                h("div", {className: "qc-note"}, "Open the selected DM and clear any plaintext in the Discord composer before attaching. This preview keeps your message.")),
            h(R.Fragment, null, h(Tabs, {label: "Review views", items: [["summary", "Recovered text"], ["decaps", "Decapsulation"], ["file", "Exact file"]], value: reviewTab, onChange: setReviewTab}),
                reviewTab === "summary" ? h(R.Fragment, null, h("blockquote", {className:"qc-plaintext"}, draft.recovery.text),
                    p(hasBOM ? "A leading UTF-8 BOM is preserved in the recovered message." : "No BOM was added to your message."),
                    h("div", {className: "qc-flow"}, h("span",null,"ML-KEM → K"),h("span",null,"HKDF → wrapping key"),h("span",null,"AES-GCM → text")),
                    p("The attachment contains ciphertext and public metadata. It contains no private keys, random m, or unwrapped symmetric keys. It does not authenticate the sender.")) :
                reviewTab === "decaps" ? h(R.Fragment, null, formula("w = v′ − NTT⁻¹(ŝᵀ ∘ NTT(u′))"), h(Polynomial, {values:draft.recovery.w,name:"My envelope's w"}),
                    p("Compress₁(w) recovers m′. ML-KEM re-encrypts and compares c′ with c; a mismatch selects J(z ∥ c), causing AES authentication to fail.")) :
                h(R.Fragment, null, p("Exact attachment · UTF-8 JSON without a BOM"), h("pre", {className:"qc-json"}, draft.wire))));
        }
        if (stopped) return h("div", {className: "qc-panel"}, h("h2", null, "Qcord is stopped"), p("Enable the plugin and reopen the composer."));
        return h("div", {className: "qc-panel qc-composer"},
            h("header", {className: "qc-header"}, h("div", null,h("span",{className:"qc-eyebrow"},"QCORD / LEARNING EDITION"),h("h2",null,"A message, made private")),
                h("div",{className:"qc-row"},h("label",{className:"qc-toggle"},h("input",{type:"checkbox",role:"switch",checked:enabled,disabled:busy,onChange:e=>{plugin.setEnabled(e.target.checked);setEnabled(plugin.enabled);}}),h("span",null,"Quantum conversations",h("small",null,enabled?"Automatic encryption + decryption on":"Automatic encryption + decryption off"))), onClose && button("Close",onClose,{"aria-label":"Close Qcord composer"}))),
            h("div", {className:"qc-toolbar"},field("ML-KEM parameter set",h("select",{value:scheme,disabled:busy,onChange:e=>changeScheme(e.target.value)},Object.entries(PARAMETER_SETS).map(([s,v])=>h("option",{key:s,value:s},v.label)))),
                h("div", {className:"qc-level", "aria-live":"polite"}, h("span",null,"NIST security level"), h("strong",null,`Level ${params.category}`)),
                button(h(R.Fragment,null,profile && h(Avatar,{profile}),h("span",null,h("strong",null,profile?.displayName || "Choose a recipient"),h("small",null,row?`${profile.username} · ${params.label} key saved`:`${params.label} key needed`))),()=>setContactsOpen(true),{className:"qc-recipient",disabled:busy,"aria-haspopup":"dialog","aria-label":"Choose recipient"}),
                button("Contacts & keys",()=>setContactsOpen(true),{disabled:busy,"aria-haspopup":"dialog"})),
            h(Tabs, {label:"Composition steps",items:stageNames.map((name,i)=>[i,`${i+1}. ${name}`]),value:step,onChange:navigate,disabled:busy}),
            h("main", {className:"qc-main",role:"tabpanel","aria-label":`${stageNames[step]} stage`,"aria-busy":busy}, content),
            h("aside", {className:"qc-source"},`Lecture 6 · slides ${pages} · PQC_Lecture_6_ML-KEM_v3.pdf`,detail && h("span",null,detail)),
            h("div", {className:"qc-feedback"},h("div",{role:"alert",className:"qc-error"},error),h("div",{role:"status"},busy?"Working locally…":notice)),
            h("footer", {className:"qc-footer"},button("Back",()=>navigate(step-1),{disabled:busy||step===0}),h("span",{className:"qc-muted"},attached?"Attached · review it in Discord":`Step ${step+1} of 5 · ${params.label}`),
                step<4?button("Next",()=>navigate(step+1),{className:"qc-primary",disabled:busy||!text||(step>=2&&!row)}):button(attached?"Attached":"Attach .qcord to composer",()=>run(async()=>{await plugin.stageLearningDraft(draft);if(alive.current){setAttached(true);setNotice("Attached. Close this panel and press Send in Discord.");}}),{className:"qc-primary",disabled:busy||attached||!draft})),
            contactsOpen && h(Contacts,{plugin,scheme,channel,keys,onClose:()=>setContactsOpen(false),onChanged:refreshed,onSelect:id=>{invalidate();setChannel(id);setPartners(plugin.getSavedPartners());}}));
    }
    return h(Panel);
};
