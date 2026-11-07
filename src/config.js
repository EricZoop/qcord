"use strict";

const {KEY_STORE, ACTIVE_SCHEME} = require("./constants");
const load = name => BdApi.Data.load(KEY_STORE, name);
const save = (name, value) => BdApi.Data.save(KEY_STORE, name, value);
const obsolete = ["learning_key_pairs", "learning_dm_partners", "learning_parameter_set", "learning_config_version",
    "learning_quantum_conversations", "key_pairs", "dm_partners", "parameter_set", "quantum_conversations",
    "encrypt_outgoing_messages", "decrypt_incoming_messages"];
function clean() { for (const name of obsolete) BdApi.Data.delete(KEY_STORE, name); }

function initialize() {
    const version = load("config_version");
    if (version === 3) { clean(); return; }
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
    save("config_version", 3);
    // Always clean, including configs already migrated by the previous release.
    clean();
}

function reset(keys) {
    clean();
    save("public_encaps", Buffer.from(keys.publicKey.bytes).toString("base64"));
    save("private_decaps", Buffer.from(keys.privateKey.bytes).toString("base64"));
    save("recipients", []);
    save("config_version", 3);
}
module.exports = {load, save, initialize, reset};
