"use strict";

const {KEY_STORE, ACTIVE_SCHEME} = require("./constants");

// Keep BetterDiscord's cache authoritative; never rewrite a cached config on disk.
const load = name => BdApi.Data.load(KEY_STORE, name);
const save = (name, value) => BdApi.Data.save(KEY_STORE, name, value);

function migrateConfiguration() {
    const version = load("config_version");
    if (version === 2) return;
    if (version !== undefined && version !== null) throw new Error("Unsupported Qcord configuration version.");
    const legacyPairs = load("keyPairs") ?? {};
    const legacyRecipients = load("recipients") ?? {};
    const isObject = value => value && typeof value === "object" && !Array.isArray(value);
    if (!isObject(legacyPairs) || !isObject(legacyRecipients)) throw new Error("Invalid legacy Qcord configuration; saved data was left unchanged.");
    const keyPairs = {};
    const partners = [];
    for (const [algorithm, pair] of Object.entries(legacyPairs)) {
        if (!isObject(pair) || typeof pair.publicKey !== "string" || typeof pair.privateKey !== "string") {
            throw new Error("Invalid legacy key pair; saved data was left unchanged.");
        }
        keyPairs[algorithm] = {
            public_key_spki_base64: pair.publicKey,
            private_key_pkcs8_base64: pair.privateKey,
            created_at: pair.createdAt
        };
    }
    for (const [channelId, algorithms] of Object.entries(legacyRecipients)) {
        if (!isObject(algorithms) || !Array.isArray(algorithms[ACTIVE_SCHEME] ?? [])) {
            throw new Error("Invalid legacy recipients; saved data was left unchanged.");
        }
        for (const row of algorithms[ACTIVE_SCHEME] ?? []) {
            if (!isObject(row) || typeof row.userId !== "string" || typeof row.publicKey !== "string") {
                throw new Error("Invalid legacy recipient; saved data was left unchanged.");
            }
            partners.push({channel_id: channelId, user_id: row.userId,
                key_algorithm: ACTIVE_SCHEME, public_key_spki_base64: row.publicKey});
        }
    }
    // Mark the migration complete only after every value was saved successfully.
    // A cleared config can contain new switch values before another key is created.
    save("encrypt_outgoing_messages", (load("encrypt_outgoing_messages") ?? load("enabled")) === true);
    save("decrypt_incoming_messages", (load("decrypt_incoming_messages") ?? load("decodeIncoming")) !== false);
    save("key_pairs", keyPairs);
    save("dm_partners", partners);
    save("config_version", 2);
    for (const name of ["enabled", "decodeIncoming", "keyPairs", "recipients"]) BdApi.Data.delete(KEY_STORE, name);
}

module.exports = {load, save, migrateConfiguration};
