"use strict";

const {parameters} = require("./parameters");
const {encode, decode} = require("./mlkem");
const {MAX_DECODED_FILE_SIZE} = require("./constants");

function fromCiphertext(ciphertext, scheme) {
    const {k, du, dv, ciphertextBytes} = parameters(scheme);
    if (ciphertext.length !== ciphertextBytes) throw new Error("Invalid ML-KEM ciphertext length.");
    const width = 32 * du;
    return {qcord_version: 4, parameter_set: scheme,
        u: Array.from({length: k}, (_, i) => decode(ciphertext.slice(i * width, (i + 1) * width), du)),
        v: decode(ciphertext.slice(k * width), dv)};
}

function toCiphertext(file) {
    if (!file || typeof file !== "object" || Array.isArray(file) || file.qcord_version !== 4) throw new Error("Expected a version-4 ML-KEM Qcord file.");
    if (Object.keys(file).sort().join() !== "parameter_set,qcord_version,u,v") throw new Error("Unexpected Qcord file fields.");
    const {k, du, dv} = parameters(file.parameter_set);
    const valid = (p, d) => Array.isArray(p) && p.length === 256 && p.every(x => Number.isInteger(x) && x >= 0 && x < 2 ** d);
    if (!Array.isArray(file.u) || file.u.length !== k || !file.u.every(p => valid(p, du)) || !valid(file.v, dv)) throw new Error("Invalid compressed u or v coefficients.");
    return Buffer.concat([...file.u.map(p => Buffer.from(encode(p, du))), Buffer.from(encode(file.v, dv))]);
}

function parse(text) {
    if (typeof text !== "string" || Buffer.byteLength(text) > MAX_DECODED_FILE_SIZE) throw new Error("Qcord file is too large or invalid.");
    const packet = JSON.parse(text.replace(/^\uFEFF/, ""));
    return {packet, ciphertext: toCiphertext(packet)};
}
module.exports = {fromCiphertext, toCiphertext, parse};
