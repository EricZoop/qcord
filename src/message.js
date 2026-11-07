"use strict";

const {gcm} = require("@noble/ciphers/aes.js");
const {sha3_256, sha3_512} = require("@noble/hashes/sha3.js");
const {randomBytes} = require("./pqc");
const {decodeBase64, aad} = require("./packet");
const {MAX_DECODED_FILE_SIZE} = require("./constants");

function keyFromM(m, ek) {
    if (m.length !== 32 || ek.length !== 1184) throw new Error("Expected 32-byte m and ML-KEM-768 public key.");
    const kr = sha3_512(Uint8Array.from([...m, ...sha3_256(ek)]));
    try { return kr.slice(0, 32); } finally { kr.fill(0); }
}

function seal(text, key, file) {
    if (typeof text !== "string") throw new Error("Enter a text message.");
    const input = new TextEncoder().encode(text);
    if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Message is too large.");
    if (new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(input) !== text) throw new Error("Your text contains an unpaired Unicode surrogate.");
    const nonce = randomBytes(12);
    try {
        const sealed = Buffer.from(gcm(Uint8Array.from(key), nonce, Uint8Array.from(aad(file))).encrypt(input));
        return {nonce_base64: Buffer.from(nonce).toString("base64"), ciphertext_base64: sealed.subarray(0, -16).toString("base64"), authentication_tag_base64: sealed.subarray(-16).toString("base64")};
    } finally { input.fill(0); }
}

function open(file, key) {
    const sealed = file.encrypted_message;
    const nonce = decodeBase64(sealed.nonce_base64, 12);
    const ciphertext = Buffer.concat([decodeBase64(sealed.ciphertext_base64), decodeBase64(sealed.authentication_tag_base64, 16)]);
    let plaintext;
    try {
        plaintext = gcm(Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(aad(file))).decrypt(Uint8Array.from(ciphertext));
        return new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(plaintext);
    } catch { throw new Error("Could not decrypt this message: wrong key or modified file."); }
    finally { plaintext?.fill(0); }
}
module.exports = {keyFromM, seal, open};
