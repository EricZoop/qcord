"use strict";

const {KEY_STORE, ACTIVE_SCHEME} = require("./constants");
const load = name => BdApi.Data.load(KEY_STORE, name);
const save = (name, value) => BdApi.Data.save(KEY_STORE, name, value);
function initialize() {
    const version = load("config_version");
    if (version === 2) return;
    if (version != null && version !== 1) throw new Error("Unsupported Qcord configuration.");
    const {PQC} = require("./pqc");
    const raw = key => Buffer.from(key.bytes).toString("base64");
    // One-time import of the previous edition's identities and contact bindings.
    const oldPairs = load("learning_key_pairs") || load("key_pairs") || {};
    const pairs = Object.fromEntries(Object.entries(oldPairs).map(([scheme, pair]) => [scheme, {
        public_encaps: raw(PQC.createPublicKey(pair.public_key_spki_base64)),
        private_decaps: raw(PQC.createPrivateKey(pair.private_key_pkcs8_base64))
    }]));
    const oldRecipients = load("learning_dm_partners") || load("dm_partners") || [];
    const recipients = oldRecipients.map(row => ({channel_id: row.channel_id, user_id: row.user_id,
        public_encaps: raw(PQC.createPublicKey(row.public_key_spki_base64)), encapsulations: []}));
    save("key_pairs", pairs);
    save("recipients", recipients);
    save("parameter_set", load("learning_parameter_set") || load("parameter_set") || ACTIVE_SCHEME);
    save("config_version", 2);
    for (const key of ["learning_key_pairs", "learning_dm_partners", "learning_parameter_set", "learning_config_version", "learning_quantum_conversations", "dm_partners", "quantum_conversations"]) {
        BdApi.Data.delete?.(KEY_STORE, key);
    }
}
module.exports = {load, save, initialize};
