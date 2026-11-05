"use strict";

// FIPS 203, Tables 2 and 3; Lecture 6, slides 56, 64, 102.
const PARAMETER_SETS = Object.freeze({
    "ml-kem-512": Object.freeze({label: "ML-KEM-512", k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, publicBytes: 800, privateBytes: 1632, ciphertextBytes: 768, category: 1}),
    "ml-kem-768": Object.freeze({label: "ML-KEM-768", k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, publicBytes: 1184, privateBytes: 2400, ciphertextBytes: 1088, category: 3}),
    "ml-kem-1024": Object.freeze({label: "ML-KEM-1024", k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, publicBytes: 1568, privateBytes: 3168, ciphertextBytes: 1568, category: 5})
});
function parameters(scheme) {
    if (!Object.hasOwn(PARAMETER_SETS, scheme)) throw new Error("Unsupported ML-KEM parameter set.");
    return PARAMETER_SETS[scheme];
}
module.exports = {PARAMETER_SETS, parameters};
