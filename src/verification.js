"use strict";

const createUI = require("./ui");
const DSA = require("./mldsa");
const hex = bytes => Buffer.from(bytes).toString("hex");

module.exports = function verificationPanel(plugin, result, {onClose, onUpdate, downloadUrl} = {}) {
    const R = BdApi.React, {h, p, button, field, formula, code, Icon, Tabs, Variables, Polynomial} = createUI(R);
    const stages = ["Sender key", "Rebuild commitment", "Check challenge"];
    function Panel() {
        const [step, setStep] = R.useState(0), [row, setRow] = R.useState(0);
        const [verification, setVerification] = R.useState(null), [error, setError] = R.useState("");
        R.useEffect(() => {
            let active = true;
            const timer = setTimeout(() => {
                try {
                    const value = plugin.verifyFileSignature(result, true, true);
                    if (active) { setVerification(value); }
                } catch (e) { if (active) setError(e.message); }
            }, 0);
            return () => { active = false; clearTimeout(timer); };
        }, []);
        R.useEffect(() => {
            if (verification && (step === 2 || !verification.trace)) onUpdate?.(verification);
        }, [step, verification]);
        const t = verification?.trace, params = DSA.parameters(result.scheme);
        const sigma = result.file.signature_sigma;
        const status = verification?.status || "checking";
        const title = status === "verified" ? "Signature verified" : status === "failed" ? "Signature failed" : status === "checking" ? "Checking signature…" : "Signature not verified";
        let left, right;
        if (!verification || !t) {
            left = h(R.Fragment, null, h("h3", null, title), p(error || verification?.reason || "Checking the saved sender key and the signature…"));
            right = p("The walkthrough needs a signed file and the sender's matching public signature key saved locally. The file itself cannot choose a trusted key.");
        } else if (step === 0) {
            left = h(R.Fragment, null,
                h(Variables, {items: [["pk = (ρ, t₁)", `${params.label} · ${verification.keySource}`], ["q / d", "8380417 / 13"], ["k / ℓ", `${params.k} / ${params.l}`], ["σ = (c̃, z, h)", `${verification.signatureBytes} encoded bytes`]]}),
                h("h3", null, "Start with the saved sender key"),
                p("This key comes from your local identity or saved contact. Compare it with the sender through a trusted channel when you first exchange keys."),
                formula("A = ExpandA(ρ)"),
                p("The public seed rebuilds A. The encoded public vector t₁ stores the high part of t, with 320 bytes per polynomial."),
                formula("tr = H(pk),   μ = H(tr ∥ M′)"),
                p(`Qcord signs the canonical encrypted envelope (${verification.payloadBytes} bytes): kem, nonce, encrypted message, and GCM tag. Pure ML-DSA formats it as M′ = 0 ∥ 0 ∥ M for an empty context.`));
            right = h(R.Fragment, null,
                field("Saved public signature key", h("textarea", {readOnly: true, rows: 4, value: verification.publicKey})),
                h("div", {className: "qc-keyparts qc-signature-parts"},
                    h("div", null, h("strong", null, "ρ seed"), h("span", null, "32 bytes")),
                    h("div", null, h("strong", null, "Encoded t₁"), h("span", null, `${320 * params.k} bytes · ${params.k} polynomials`))),
                code(`ρ · ${hex(t.rho)}`), code(`tr · ${hex(t.tr)}`), code(`μ · ${hex(t.mu)}`));
        } else if (step === 1) {
            left = h(R.Fragment, null, h("h3", null, "Rebuild the signer's commitment"),
                p("Lecture 8, slides 10, 17 and 25: the response z = y + cs₁ lets the verifier reconstruct the commitment without learning the secret."),
                formula("Az − ct = A(y + cs₁) − c(As₁ + s₂)"), formula("Az − ct = w − cs₂"),
                p("The lecture's simplified check compares the high bits. Full ML-DSA uses the rounded public key and the hint vector h:"),
                formula("c = SampleInBall(c̃)"),
                formula("w′ = Az − c · t₁ · 2ᵈ  (mod q)"),
                formula("w′₁ = UseHint(h, w′)"),
                p("Each hint corrects a high-bit boundary affected by the omitted low bits. The values shown are reconstructed from this file and the saved key."));
            right = h(R.Fragment, null,
                h("div", {className: "qc-row qc-verification-rows", "aria-label": "Commitment polynomial"}, Array.from({length: params.k}, (_, i) => button(`w′₁[${i}]`, () => setRow(i), {key: i, "aria-pressed": row === i}))),
                h(Polynomial, {values: t.w1[row], name: `w′₁[${row}] · reconstructed high bits`, modulus: (DSA.Q - 1) / (2 * params.gamma2)}),
                code(`h[${row}] · nonzero positions: ${sigma.h[row].join(", ") || "none"}`),
                h("details", null, h("summary", null, h(Icon, {name: "chevron"}), "Approximate commitment before UseHint"), code(t.wApprox[row].join(", "))));
        } else {
            left = h(R.Fragment, null, h("h3", null, "Compare the challenge hashes"),
                p("Lecture 8, slides 17 and 25:"), formula("H(M ∥ HighBits(Az − ct)) = c"),
                p("Full ML-DSA hashes the message representative and the encoded, hint-corrected high bits:"),
                formula("c̃′ = H(μ ∥ w1Encode(w′₁))"), formula("c̃′ = c̃"),
                formula("‖z‖∞ < γ₁ − β,   weight(h) ≤ ω"),
                p("Accept only when both the challenge comparison and the bounds pass. This reconstruction is checked against the bundled ML-DSA verifier's result."));
            right = h(R.Fragment, null,
                h("div", {className: "qc-verification-result", "data-status": status, role: "status"}, h(Icon, {name: status === "verified" ? "check" : "shieldX"}), h("strong", null, title)),
                field("Received challenge c̃", h("textarea", {"aria-label": "Received challenge c tilde", readOnly: true, rows: 2, value: hex(Buffer.from(t.expected, "base64"))})),
                field("Recomputed challenge c̃′", h("textarea", {"aria-label": "Recomputed challenge c tilde prime", readOnly: true, rows: 2, value: hex(Buffer.from(t.computed, "base64"))})),
                h(Variables, {items: [["c̃′ = c̃", t.computed === t.expected ? "Match" : "Mismatch"], ["‖z‖∞ < γ₁ − β", `${t.zNorm} < ${t.zBound} · ${t.zNorm < t.zBound ? "Pass" : "Fail"}`], ["weight(h) ≤ ω", `${t.hintCount} ≤ ${t.hintBound} · ${t.hintCount <= t.hintBound ? "Pass" : "Fail"}`], ["Saved-key verification", status === "verified" ? "Pass" : "Fail"]]}),
                p(verification.reason));
        }
        return h("div", {className: "qc-panel qc-composer qc-verifier"},
            h("header", {className: "qc-label-row"}, h("h3", null, "Check Signature Challenge"), button("Go Back", onClose, {className: "qc-quiet"})),
            h(Tabs, {label: "Signature verification steps", items: stages.map((name, i) => [i, `${i + 1}. ${name}`]), value: step, onChange: setStep}),
            h("main", {className: "qc-main", "aria-busy": !verification && !error}, h("div", {className: "qc-split"}, h("section", {className: "qc-explanation"}, left), h("section", {className: "qc-visual"}, right))),
            h("footer", {className: "qc-footer"}, button("Previous step", () => setStep(step - 1), {disabled: step === 0}),
                h("span", {className: "qc-feedback", role: "status"}, error || verification?.reason || "Checking…"),
                downloadUrl && h("a", {className: "qc-file-link", href: downloadUrl, download: true}, h(Icon, {name: "upload"}), "Download .qcord"),
                step < 2 ? button("Next", () => setStep(step + 1), {className: "qc-primary", disabled: !t}) : button("Done", onClose, {className: "qc-primary"})));
    }
    return h(Panel);
};
