"use strict";

// FIPS 203, Tables 2 and 3.
const PARAMETER_SETS = Object.freeze({
    "ml-kem-768": Object.freeze({label: "ML-KEM-768", k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, publicBytes: 1184, privateBytes: 2400, ciphertextBytes: 1088, category: 3}),
});
function parameters(scheme = "ml-kem-768") {
    if (!Object.hasOwn(PARAMETER_SETS, scheme)) throw new Error("Qcord supports ML-KEM-768 only.");
    return PARAMETER_SETS[scheme];
}
module.exports = {PARAMETER_SETS, parameters};
