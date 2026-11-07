"use strict";

// Fixed, PUBLIC example secrets. Never use these keys or m for a real exchange.
const {mkdirSync, writeFileSync} = require("node:fs");
const {ml_kem768} = require("@noble/post-quantum/ml-kem.js");
const {fromCiphertext} = require("../src/packet");
const raw = bytes => Buffer.from(bytes).toString("base64");
const recipient = ml_kem768.keygen(Uint8Array.from({length: 64}, (_, i) => i));
const sender = ml_kem768.keygen(Uint8Array.from({length: 64}, (_, i) => 64 + i));
const m = Uint8Array.from({length: 32}, (_, i) => 128 + i);
const encapsulated = ml_kem768.encapsulate(recipient.publicKey, m);
mkdirSync("schemas", {recursive: true});
const write = (path, data) => writeFileSync(path, JSON.stringify(data, null, 2) + "\n");
write("schemas/example.qcord", fromCiphertext(encapsulated.cipherText, "ml-kem-768"));
write("schemas/example.qcord.config.json", {config_version: 2, parameter_set: "ml-kem-768",
    key_pairs: {"ml-kem-768": {public_encaps: raw(sender.publicKey), private_decaps: raw(sender.secretKey)}},
    recipients: [{channel_id: "100", user_id: "2", public_encaps: raw(recipient.publicKey), encapsulations: [{m: raw(m)}]}]});
write("schemas/example.recipient.config.json", {config_version: 2, parameter_set: "ml-kem-768",
    key_pairs: {"ml-kem-768": {public_encaps: raw(recipient.publicKey), private_decaps: raw(recipient.secretKey)}}, recipients: []});
