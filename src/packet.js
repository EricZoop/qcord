"use strict";

const {parameters, PARAMETER_SETS} = require("./parameters");
const {encode, decode} = require("./mlkem");
const {MAX_DECODED_FILE_SIZE} = require("./constants");
const coefficients = file => file?.qcord_version === 6 ? file.kem : file;
const schemeOf = file => Object.keys(PARAMETER_SETS).find(name => parameters(name).k === coefficients(file)?.u?.length);

function fromCiphertext(ciphertext, scheme = "ml-kem-768") {
    const {k, du, dv, ciphertextBytes} = parameters(scheme);
    if (ciphertext.length !== ciphertextBytes) throw new Error("Invalid ML-KEM ciphertext length.");
    const width = 32 * du;
    return {qcord_version: 6, kem: {
        u: Array.from({length: k}, (_, i) => decode(ciphertext.slice(i * width, (i + 1) * width), du)),
        v: decode(ciphertext.slice(k * width), dv)}, signature_sigma: {c_tilde: "", z: [], h: []}};
}

function toCiphertext(file) {
    if (!file || typeof file !== "object" || Array.isArray(file) || ![5, 6].includes(file.qcord_version)) throw new Error("Expected a version-5 or version-6 Qcord file.");
    const scheme = schemeOf(file);
    if (!scheme) throw new Error("Invalid compressed u or v coefficients.");
    const {k, du, dv} = parameters(scheme);
    const kem = coefficients(file);
    if (file.qcord_version === 6 && (!kem || Array.isArray(kem) || Object.keys(kem).sort().join() !== "u,v")) throw new Error("Invalid kem fields.");
    const valid = (p, d) => Array.isArray(p) && p.length === 256 && p.every(x => Number.isInteger(x) && x >= 0 && x < 2 ** d);
    if (!Array.isArray(kem.u) || kem.u.length !== k || !kem.u.every(p => valid(p, du)) || !valid(kem.v, dv)) throw new Error("Invalid compressed u or v coefficients.");
    return Buffer.concat([...kem.u.map(p => Buffer.from(encode(p, du))), Buffer.from(encode(kem.v, dv))]);
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
    const expected = packet.qcord_version === 6 ? "encrypted_message,kem,qcord_version" : "encrypted_message,qcord_version,u,v";
    if (Object.keys(packet).filter(key => key !== "signature_sigma").sort().join() !== expected) throw new Error("Unexpected Qcord file fields.");
    if (packet.signature_sigma !== undefined) validateSignaturePlaceholder(packet.signature_sigma);
    const sealed = packet.encrypted_message;
    if (!sealed || typeof sealed !== "object" || Array.isArray(sealed) || Object.keys(sealed).sort().join() !== "authentication_tag_base64,ciphertext_base64,nonce_base64") throw new Error("Invalid encrypted_message fields.");
    decodeBase64(sealed.nonce_base64, 12);
    decodeBase64(sealed.authentication_tag_base64, 16);
    decodeBase64(sealed.ciphertext_base64);
    return {packet, ciphertext};
}
// Reserved fields are blank until signing and verification are implemented.
function validateSignaturePlaceholder(sigma) {
    if (!sigma || typeof sigma !== "object" || Array.isArray(sigma)
        || Object.keys(sigma).sort().join() !== "c_tilde,h,z" || sigma.c_tilde !== ""
        || !Array.isArray(sigma.z) || sigma.z.length || !Array.isArray(sigma.h) || sigma.h.length) {
        throw new Error("Expected blank signature_sigma placeholders; ML-DSA is not implemented.");
    }
}

// Authenticate the canonical ciphertext structure, independent of JSON formatting.
const aad = file => Buffer.from(JSON.stringify(file.qcord_version === 6
    ? {qcord_version: 6, kem: {u: file.kem.u, v: file.kem.v}}
    : {qcord_version: 5, u: file.u, v: file.v}));

function stringify(file) {
    toCiphertext(file);
    // Keep each polynomial on one line; whitespace does not change authenticated data.
    const kem = coefficients(file), nested = file.qcord_version === 6;
    const indent = nested ? "      " : "    ";
    const rows = kem.u.map(poly => indent + "[" + poly.join(", ") + "]").join(",\n");
    const vectors = nested ? `  "kem": {\n    "u": [\n${rows}\n    ],\n    "v": [${kem.v.join(", ")}]\n  }` : `  "u": [\n${rows}\n  ],\n  "v": [${kem.v.join(", ")}]`;
    const sealed = JSON.stringify(file.encrypted_message, null, 2).replace(/\n/g, "\n  ");
    const sigma = file.signature_sigma;
    if (sigma !== undefined) validateSignaturePlaceholder(sigma);
    const signature = sigma === undefined ? "" : `,\n  "signature_sigma": ${JSON.stringify(sigma, null, 2).replace(/\n/g, "\n  ")}`;
    return `{\n  "qcord_version": ${file.qcord_version},\n${vectors},\n  "encrypted_message": ${sealed}${signature}\n}\n`;
}
module.exports = {schemeOf, fromCiphertext, toCiphertext, parse, decodeBase64, aad, stringify};
