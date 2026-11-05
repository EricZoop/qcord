"use strict";

const {PQC, randomBytes} = require("./pqc");
const {gcm} = require("@noble/ciphers/aes.js");
const {sha256} = require("@noble/hashes/sha2.js");
const {hkdf} = require("@noble/hashes/hkdf.js");
const config = require("./config");
const {parameters} = require("./parameters");
const bytes = value => Uint8Array.from(value);
const { ACTIVE_SCHEME, BASE64_RE, MAX_DECODED_FILE_SIZE } = require("./constants");

module.exports = class MessageCrypto {
    async generateKeys(scheme) {
        if (!this.running || this.resetting) throw new Error("Enable Qcord first.");
        parameters(scheme);
        if (this.keyPairs.has(scheme)) return this.keyPairs.get(scheme);
        if (this.keyTasks.has(scheme)) return this.keyTasks.get(scheme);
        const session = this.session;
        const task = (async () => {
            const stored = config.load("key_pairs") || {};
            if (typeof stored !== "object" || Array.isArray(stored)) throw new Error("Invalid saved key configuration.");
            let keys;
            if (stored[scheme]) {
                const {public_key_spki_base64: publicKey, private_key_pkcs8_base64: privateKey, created_at: createdAt} = stored[scheme];
                keys = {scheme, createdAt, publicKey: PQC.createPublicKey(publicKey), privateKey: PQC.createPrivateKey(privateKey)};
                if (keys.publicKey.asymmetricKeyType !== scheme || keys.privateKey.asymmetricKeyType !== scheme ||
                    !PQC.createPublicKey(keys.privateKey).equals(keys.publicKey)) {
                    throw new Error("Saved keys do not match. Restore your key configuration from backup.");
                }
            }
            else {
                keys = {scheme, ...await PQC.generateKeyPair(scheme)};
                keys.createdAt = new Date().toISOString();
                if (!this.running || this.session !== session) throw new Error("Qcord stopped during key generation.");
                // Read again after async keygen so simultaneous parameter sets cannot overwrite one another.
                config.save("key_pairs", {
                    ...config.load("key_pairs"),
                    [scheme]: {
                        public_key_spki_base64: keys.publicKey.export({type: "spki", format: "base64"}),
                        private_key_pkcs8_base64: keys.privateKey.export({type: "pkcs8", format: "base64"}),
                        created_at: keys.createdAt
                    }
                });
                config.save("config_version", 1);
            }
            if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
            this.keyPairs.set(scheme, keys);
            this.keys = keys;
            return keys;
        })();
        this.keyTasks.set(scheme, task);
        try { return await task; }
        finally { if (this.keyTasks.get(scheme) === task) this.keyTasks.delete(scheme); }
    }

    keyId(publicKey) {
        return Buffer.from(sha256(bytes(publicKey.export({type: "spki", format: "der"})))).toString("hex");
    }

    getRecipients(channelId, scheme) {
        return this.getSavedPartners().filter(row => row.channel_id === channelId && row.key_algorithm === scheme);
    }

    getSavedPartners() {
        const partners = config.load("dm_partners") || [];
        if (!Array.isArray(partners)) throw new Error("Invalid saved DM partners.");
        return partners;
    }

    getPartnerProfile(userId) {
        const user = BdApi.Webpack.getStore?.("UserStore")?.getUser(userId);
        const username = user?.username ? "@" + user.username : "User " + userId;
        const avatar = typeof user?.avatar === "string" && /^[a-f0-9_]+$/i.test(user.avatar)
            ? `https://cdn.discordapp.com/avatars/${userId}/${user.avatar}.png?size=64` : null;
        return {username, displayName: user?.globalName || user?.global_name || user?.username || "Discord user", avatar};
    }

    getDirectPartner(channelId) {
        const channel = BdApi.Webpack.getStore?.("ChannelStore")?.getChannel(channelId);
        if (channel?.type !== 1 || !Array.isArray(channel.recipients) || channel.recipients.length !== 1) {
            throw new Error("Open a one-to-one DM to use Qcord encryption.");
        }
        const recipient = channel.recipients[0];
        const userId = typeof recipient === "string" ? recipient : recipient?.id;
        if (!/^\d{1,20}$/.test(userId || "")) throw new Error("Could not identify this DM's recipient.");
        return {userId, channelId};
    }

    saveRecipients(channelId, rows, scheme) {
        if (!this.running || this.resetting) throw new Error("Enable Qcord first.");
        if (!/^\d+$/.test(channelId || "")) throw new Error("Open a Discord channel first.");
        parameters(scheme);
        const partner = this.getDirectPartner(channelId);
        if (!Array.isArray(rows) || rows.length > 1) throw new Error("Save one public key for your DM partner.");
        const entries = rows.map(({user_id, public_key_spki_base64}) => {
            if (user_id !== partner.userId) throw new Error("The user ID must match this DM's recipient.");
            const key = PQC.createPublicKey(public_key_spki_base64);
            if (key.asymmetricKeyType !== scheme) throw new Error("Every recipient key must use the selected ML-KEM scheme.");
            return {channel_id: channelId, user_id, key_algorithm: scheme,
                public_key_spki_base64: key.export({type: "spki", format: "base64"}), saved_at: new Date().toISOString()};
        });
        config.save("dm_partners", [...this.getSavedPartners().filter(row => row.channel_id !== channelId || row.key_algorithm !== scheme), ...entries]);
    }

    removePartner(channelId, scheme = this.scheme || ACTIVE_SCHEME) {
        if (this.resetting || !this.running) throw new Error("Enable Qcord first.");
        config.save("dm_partners", this.getSavedPartners().filter(row => row.channel_id !== channelId || row.key_algorithm !== scheme));
    }

    decodeBytes(value, size) {
        if (typeof value !== "string" || value.length > MAX_DECODED_FILE_SIZE || !BASE64_RE.test(value)) throw new Error("Invalid encrypted file field.");
        const bytes = Buffer.from(value, "base64");
        if (bytes.toString("base64") !== value || (size !== undefined && bytes.length !== size)) throw new Error("Invalid encrypted file field.");
        return bytes;
    }

    seal(data, key, aad) {
        const iv = randomBytes(12);
        const sealed = Buffer.from(gcm(bytes(key), iv, bytes(aad)).encrypt(bytes(data)));
        return {nonce_base64: Buffer.from(iv).toString("base64"), ciphertext_base64: sealed.subarray(0, -16).toString("base64"), authentication_tag_base64: sealed.subarray(-16).toString("base64")};
    }

    openSealed(sealed, key, aad) {
        const iv = bytes(this.decodeBytes(sealed.nonce_base64, 12));
        const ciphertext = Buffer.concat([this.decodeBytes(sealed.ciphertext_base64), this.decodeBytes(sealed.authentication_tag_base64, 16)]);
        return Buffer.from(gcm(bytes(key), iv, bytes(aad)).decrypt(bytes(ciphertext)));
    }

    wrappingKey(sharedSecret, version = 3) {
        return hkdf(sha256, bytes(sharedSecret), new Uint8Array(), new TextEncoder().encode(`Qcord v${version} key wrap`), 32);
    }

    packetHeader(channelId, fingerprints, scheme = this.scheme || ACTIVE_SCHEME) {
        return {qcord_version: 3, kem_algorithm: scheme, encryption_algorithm: "aes-256-gcm",
            key_derivation_algorithm: "hkdf-sha256", channel_id: channelId, recipient_key_fingerprints_sha256: fingerprints};
    }

    async encryptMessage(channelId, text, {inspect = false, scheme = this.scheme || ACTIVE_SCHEME} = {}) {
        if (!/^\d+$/.test(channelId || "")) throw new Error("Invalid channel.");
        const params = parameters(scheme);
        const partner = this.getDirectPartner(channelId);
        const recipients = this.getRecipients(channelId, scheme);
        if (recipients.length !== 1 || recipients[0].user_id !== partner.userId) {
            throw new Error(`Save your DM partner's ${params.label} key in Qcord first.`);
        }
        if (typeof text !== "string" || !text.length) throw new Error("Write a message first.");
        const input = Buffer.from(text, "utf8");
        if (new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(input) !== text) throw new Error("Your text contains an unpaired Unicode surrogate. Remove that character before encrypting.");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Message is too large for a Qcord file.");
        const session = this.session;
        const ownKeys = await this.generateKeys(scheme);
        const publicKeys = new Map();
        for (const key of [ownKeys.publicKey, ...recipients.map(row => PQC.createPublicKey(row.public_key_spki_base64))]) {
            if (key.asymmetricKeyType !== scheme) throw new Error("Recipient key algorithm does not match.");
            publicKeys.set(this.keyId(key), key);
        }
        const header = this.packetHeader(channelId, [...publicKeys.keys()], scheme);
        const aad = Buffer.from(JSON.stringify(header));
        const payloadKey = randomBytes(32);
        const envelopes = [];
        let trace = null;
        const partnerId = this.keyId(PQC.createPublicKey(recipients[0].public_key_spki_base64));
        for (const [id, publicKey] of publicKeys) {
            const {sharedKey, ciphertext, trace: observed} = await PQC.encapsulate(publicKey, inspect && id === partnerId);
            if (observed) trace = observed;
            envelopes.push({public_key_fingerprint_sha256: id, kem_ciphertext_base64: ciphertext.toString("base64"),
                wrapped_message_key: this.seal(payloadKey, this.wrappingKey(sharedKey), Buffer.concat([aad, Buffer.from(id)]))});
            sharedKey.fill(0);
        }
        const output = JSON.stringify({...header, recipients: envelopes, encrypted_message: this.seal(input, payloadKey, aad)}, null, "\t") + "\n";
        payloadKey.fill(0);
        const fileBytes = Buffer.byteLength(output);
        if (fileBytes > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file exceeds the 1 MiB display limit. Shorten your message.");
        if (!this.running || this.session !== session) throw new Error("Qcord encryption was stopped.");
        if (!inspect) return output;
        const recovery = await this.decryptMessage(output, channelId, {inspect: true});
        if (recovery.text !== text) throw new Error("Local decryption check failed.");
        return {wire: output, packet: JSON.parse(output), trace, recovery, channelId, partnerId, scheme};
    }

    async decryptMessage(text, channelId, {inspect = false} = {}) {
        if (typeof text !== "string" || !text.trimStart().startsWith("{")) return null;
        if (Buffer.byteLength(text) > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file is too large.");
        const session = this.session;
        // A transport BOM belongs to the JSON wrapper, not the encrypted message.
        const file = JSON.parse(text.replace(/^\uFEFF/, ""));
        if (file?.qcord_version !== 3) throw new Error("This file requires a different Qcord edition.");
        const scheme = file.kem_algorithm;
        const params = parameters(scheme);
        if (!/^\d+$/.test(channelId || "") || file.channel_id !== channelId ||
            !Array.isArray(file.recipients) || !file.recipients.length || file.recipients.length > 2) throw new Error("Invalid encrypted file or wrong channel.");
        const ids = file.recipients.map(recipient => recipient?.public_key_fingerprint_sha256);
        if (ids.some(id => typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id)) || new Set(ids).size !== ids.length) throw new Error("Invalid recipient list.");
        const header = this.packetHeader(channelId, ids, scheme);
        if (file.encryption_algorithm !== header.encryption_algorithm || file.key_derivation_algorithm !== header.key_derivation_algorithm ||
            JSON.stringify(file.recipient_key_fingerprints_sha256) !== JSON.stringify(ids)) throw new Error("Invalid packet algorithms or fingerprints.");
        if (!this.keyPairs.has(scheme) && !config.load("key_pairs")?.[scheme]) throw new Error("No saved decapsulation key for this file.");
        const keys = await this.generateKeys(scheme);
        const id = this.keyId(keys.publicKey);
        const recipient = file.recipients.find(entry => entry.public_key_fingerprint_sha256 === id);
        if (!recipient) throw new Error("This file is not addressed to your key.");
        const aad = Buffer.from(JSON.stringify(header));
        const ciphertext = this.decodeBytes(recipient.kem_ciphertext_base64, params.ciphertextBytes);
        const sharedKey = await PQC.decapsulate(keys.privateKey, ciphertext);
        let payloadKey;
        try {
            payloadKey = this.openSealed(recipient.wrapped_message_key, this.wrappingKey(sharedKey), Buffer.concat([aad, Buffer.from(id)]));
            if (payloadKey.length !== 32) throw new Error("Invalid payload key.");
            const plaintext = this.openSealed(file.encrypted_message, payloadKey, aad);
            const decoded = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(plaintext);
            plaintext.fill(0);
            if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
            return inspect ? {text: decoded, ...require("./learning").decapsulationTrace(keys.privateKey.bytes, ciphertext, scheme)} : decoded;
        } finally { sharedKey.fill(0); payloadKey?.fill(0); }
    }

};
