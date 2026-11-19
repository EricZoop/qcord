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
    if (version === 5) { clean(); return; }
    if (version === 4 || version === 3) { finalize(); clean(); return; }
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
    const levels = require("./parameters").PARAMETER_SETS;
    const existing = load("key_sets") || {}, encryption = load("security_keys") || {}, signatures = load("signature_keys") || {};
    const keySets = {};
    for (const scheme of Object.keys(levels)) {
        const enc = existing[scheme] || (scheme === ACTIVE_SCHEME ? {public_encaps: load("public_encaps"), private_decaps: load("private_decaps")} : encryption[scheme]) || {};
        const sig = existing[scheme] || signatures[scheme] || {};
        keySets[scheme] = {public_encaps: enc.public_encaps || "", private_decaps: enc.private_decaps || "",
            public_signature: sig.public_signature || "", private_signature: sig.private_signature || ""};
    }
    writeConfig({auto_encrypt: load("auto_encrypt") === true, auto_decrypt: load("auto_decrypt") !== false,
        auto_verify: load("auto_verify") === true, save_receipts: load("save_receipts") !== false,
        config_version: 5, key_sets: keySets, recipients});
}

function writeConfig(fields) {
    for (const name of [...Object.keys(fields), "public_encaps", "private_decaps", "public_signature", "private_signature", "security_keys", "signature_keys"]) BdApi.Data.delete(KEY_STORE, name);
    for (const [name, value] of Object.entries(fields)) save(name, value);
}

function saveKeySet(scheme, updates) {
    const sets = load("key_sets") || {};
    const value = {...sets[scheme], ...updates};
    sets[scheme] = {public_encaps: value.public_encaps || "", private_decaps: value.private_decaps || "",
        public_signature: value.public_signature || "", private_signature: value.private_signature || ""};
    save("key_sets", sets);
}

function reset(keys) {
    clean();
    const sets = {};
    for (const scheme of Object.keys(require("./parameters").PARAMETER_SETS)) {
        sets[scheme] = {public_encaps: scheme === ACTIVE_SCHEME ? Buffer.from(keys.publicKey.bytes).toString("base64") : "",
            private_decaps: scheme === ACTIVE_SCHEME ? Buffer.from(keys.privateKey.bytes).toString("base64") : "", public_signature: "", private_signature: ""};
    }
    writeConfig({auto_encrypt: false, auto_decrypt: true, auto_verify: false, save_receipts: true, config_version: 5, key_sets: sets, recipients: []});
}
module.exports = {load, save, saveKeySet, initialize, reset, get receiptsRevision() { return receiptsRevision; }};
