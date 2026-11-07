"use strict";

const {parameters} = require("./parameters");
const {encode, decode} = require("./mlkem");
const {MAX_DECODED_FILE_SIZE} = require("./constants");
const {k, du, dv, ciphertextBytes} = parameters();

function fromCiphertext(ciphertext) {
    if (ciphertext.length !== ciphertextBytes) throw new Error("Invalid ML-KEM-768 ciphertext length.");
    const width = 32 * du;
    return {qcord_version: 5,
        u: Array.from({length: k}, (_, i) => decode(ciphertext.slice(i * width, (i + 1) * width), du)),
        v: decode(ciphertext.slice(k * width), dv)};
}

function toCiphertext(file) {
    if (!file || typeof file !== "object" || Array.isArray(file) || file.qcord_version !== 5) throw new Error("Expected a version-5 ML-KEM-768 Qcord file.");
    const valid = (p, d) => Array.isArray(p) && p.length === 256 && p.every(x => Number.isInteger(x) && x >= 0 && x < 2 ** d);
    if (!Array.isArray(file.u) || file.u.length !== k || !file.u.every(p => valid(p, du)) || !valid(file.v, dv)) throw new Error("Invalid compressed u or v coefficients.");
    return Buffer.concat([...file.u.map(p => Buffer.from(encode(p, du))), Buffer.from(encode(file.v, dv))]);
}

function decodeBase64(value, size) {
    if (typeof value !== "string" || value.length > MAX_DECODED_FILE_SIZE || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error("Invalid encrypted message field.");
    const bytes = Buffer.from(value, "base64");
    if (bytes.toString("base64") !== value || (size !== undefined && bytes.length !== size)) throw new Error("Invalid encrypted message field length or Base64.");
    return bytes;
}

function parse(text) {
    if (typeof text !== "string" || Buffer.byteLength(text) > MAX_DECODED_FILE_SIZE) throw new Error("Qcord file is too large or invalid.");
    const packet = JSON.parse(text.replace(/^\uFEFF/, ""));
    const ciphertext = toCiphertext(packet);
    if (Object.keys(packet).sort().join() !== "encrypted_message,qcord_version,u,v") throw new Error("Unexpected Qcord file fields.");
    const sealed = packet.encrypted_message;
    if (!sealed || typeof sealed !== "object" || Array.isArray(sealed) || Object.keys(sealed).sort().join() !== "authentication_tag_base64,ciphertext_base64,nonce_base64") throw new Error("Invalid encrypted_message fields.");
    decodeBase64(sealed.nonce_base64, 12);
    decodeBase64(sealed.authentication_tag_base64, 16);
    decodeBase64(sealed.ciphertext_base64);
    return {packet, ciphertext};
}
// Authenticate the canonical ciphertext structure, independent of JSON formatting.
const aad = file => Buffer.from(JSON.stringify({qcord_version: file.qcord_version, u: file.u, v: file.v}));

function stringify(file) {
    toCiphertext(file);
    // Keep each polynomial on one line; whitespace does not change authenticated data.
    const rows = file.u.map(poly => "    [" + poly.join(", ") + "]").join(",\n");
    const sealed = JSON.stringify(file.encrypted_message, null, 2).replace(/\n/g, "\n  ");
    return `{\n  "qcord_version": ${file.qcord_version},\n  "u": [\n${rows}\n  ],\n  "v": [${file.v.join(", ")}],\n  "encrypted_message": ${sealed}\n}\n`;
}
module.exports = {fromCiphertext, toCiphertext, parse, decodeBase64, aad, stringify};
