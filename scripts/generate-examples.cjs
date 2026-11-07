"use strict";

// Fixed, PUBLIC example secrets. Never use these keys or m for a real exchange.
const {mkdirSync, writeFileSync} = require("node:fs");
const {ml_kem768} = require("@noble/post-quantum/ml-kem.js");
const {fromCiphertext, aad, stringify} = require("../src/packet");
const {gcm} = require("@noble/ciphers/aes.js");
const raw = bytes => Buffer.from(bytes).toString("base64");
const recipient = ml_kem768.keygen(Uint8Array.from({length: 64}, (_, i) => i));
const sender = ml_kem768.keygen(Uint8Array.from({length: 64}, (_, i) => 64 + i));
const m = Uint8Array.from({length: 32}, (_, i) => 128 + i);
const encapsulated = ml_kem768.encapsulate(recipient.publicKey, m);
mkdirSync("schemas", {recursive: true});
const write = (path, data) => writeFileSync(path, JSON.stringify(data, null, 2) + "\n");
const file = fromCiphertext(encapsulated.cipherText);
const nonce = Uint8Array.from({length: 12}, (_, i) => 200 + i); // PUBLIC example only.
const sealed = gcm(encapsulated.sharedSecret, nonce, Uint8Array.from(aad(file))).encrypt(new TextEncoder().encode("Hello from Qcord."));
file.encrypted_message = {nonce_base64: raw(nonce), ciphertext_base64: raw(sealed.slice(0, -16)), authentication_tag_base64: raw(sealed.slice(-16))};
writeFileSync("schemas/example.qcord", stringify(file));
write("schemas/example.qcord.config.json", {config_version: 3,
    public_encaps: raw(sender.publicKey), private_decaps: raw(sender.secretKey),
    recipients: [{channel_id: "100", user_id: "2", public_encaps: raw(recipient.publicKey), encapsulations: [{m: raw(m)}]}]});
write("schemas/example.recipient.config.json", {config_version: 3,
    public_encaps: raw(recipient.publicKey), private_decaps: raw(recipient.secretKey), recipients: []});
