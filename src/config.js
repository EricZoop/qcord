"use strict";

const {KEY_STORE, ACTIVE_SCHEME} = require("./constants");
const load = name => BdApi.Data.load(KEY_STORE, name);
let receiptsRevision = 0;
function save(name, value) {
    if (name === "recipients") receiptsRevision++;
    BdApi.Data.save(KEY_STORE, name, value);
    if (name !== "recipients") {
        const recipients = load("recipients");
        if (recipients !== undefined) {
            BdApi.Data.delete(KEY_STORE, "recipients");
            BdApi.Data.save(KEY_STORE, "recipients", recipients);
        }
    }
}
const obsolete = ["learning_key_pairs", "learning_dm_partners", "learning_parameter_set", "learning_config_version",
    "learning_quantum_conversations", "key_pairs", "dm_partners", "parameter_set", "quantum_conversations",
    "encrypt_outgoing_messages", "decrypt_incoming_messages"];
function clean() { for (const name of obsolete) BdApi.Data.delete(KEY_STORE, name); }

function initialize() {
    const version = load("config_version");
    if (version === 4) {
        if (load("public_signature") === undefined || load("private_signature") === undefined) finalize();
        clean(); return;
    }
    if (version === 3) { finalize(); clean(); return; }
    if (version != null && ![1, 2].includes(version)) throw new Error("Unsupported Qcord configuration.");
    const {PQC} = require("./pqc");
    const raw = key => Buffer.from(key.bytes).toString("base64");
    // Prefer the current identity over stale prefixed copies. Only 768 is retained.
    const pair = load("key_pairs")?.[ACTIVE_SCHEME] || load("learning_key_pairs")?.[ACTIVE_SCHEME];
    let publicKey, privateKey;
    if (pair) {
        publicKey = PQC.createPublicKey(pair.public_encaps || pair.public_key_spki_base64);
        privateKey = PQC.createPrivateKey(pair.private_decaps || pair.private_key_pkcs8_base64);
        if (!PQC.createPublicKey(privateKey).equals(publicKey)) throw new Error("Saved public and private keys do not match.");
    }
    const rows = [...(load("recipients") || []), ...(load("learning_dm_partners") || []), ...(load("dm_partners") || [])];
    const recipients = [];
    for (const row of rows) {
        if (row.key_algorithm && row.key_algorithm !== ACTIVE_SCHEME) continue;
        if (recipients.some(r => r.channel_id === row.channel_id)) continue;
        let key;
        try { key = PQC.createPublicKey(row.public_encaps || row.public_key_spki_base64); }
        catch { continue; } // Discard contacts from unsupported parameter sets.
        recipients.push({channel_id: row.channel_id, user_id: row.user_id, public_encaps: raw(key), encapsulations: row.encapsulations || []});
    }
    if (publicKey) { save("public_encaps", raw(publicKey)); save("private_decaps", raw(privateKey)); }
    save("recipients", recipients);
    finalize();
    // Always clean, including configs already migrated by the previous release.
    clean();
}

// Older receipts have no recorded filename epoch. Preserve their derived keys.
function finalize() {
    const {PQC} = require("./pqc");
    const {keyFromM} = require("./message");
    const recipients = (load("recipients") || []).map(row => ({...row,
        encapsulations: (row.encapsulations || []).map(record => {
            if (!record.m) return record;
            const m = require("./packet").decodeBase64(record.m, 32);
            let key;
            try {
                key = keyFromM(m, PQC.createPublicKey(row.public_encaps).bytes);
                return {message_epoch: null, k: Buffer.from(key).toString("base64")};
            } finally { m.fill(0); key?.fill(0); }
        })}));
    const fields = {config_version: 4, auto_encrypt: load("auto_encrypt") === true,
        auto_decrypt: load("auto_decrypt") !== false, save_receipts: load("save_receipts") !== false,
        public_signature: load("public_signature") ?? "", private_signature: load("private_signature") ?? ""};
    for (const name of ["public_encaps", "private_decaps"]) {
        const value = load(name);
        if (value !== undefined) fields[name] = value;
    }
    fields.recipients = recipients;
    for (const name of Object.keys(fields)) BdApi.Data.delete(KEY_STORE, name);
    for (const [name, value] of Object.entries(fields)) save(name, value);
}

function reset(keys) {
    clean();
    save("public_encaps", Buffer.from(keys.publicKey.bytes).toString("base64"));
    save("private_decaps", Buffer.from(keys.privateKey.bytes).toString("base64"));
    save("recipients", []);
    save("auto_encrypt", false);
    save("auto_decrypt", true);
    save("save_receipts", true);
    save("public_signature", "");
    save("private_signature", "");
    finalize();
}
module.exports = {load, save, initialize, reset, get receiptsRevision() { return receiptsRevision; }};
