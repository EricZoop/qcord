"use strict";

const {PQC, randomBytes, equalBytes} = require("./pqc");
const {gcm} = require("@noble/ciphers/aes.js");
const {sha256} = require("@noble/hashes/sha2.js");
const {hkdf} = require("@noble/hashes/hkdf.js");
const config = require("./config");
const bytes = value => Uint8Array.from(value);
const { ACTIVE_SCHEME, ENCRYPTED_PREFIX, BASE64_RE, MAX_DECODED_FILE_SIZE } = require("./constants");

module.exports = class MessageCrypto {
    async generateKeys(scheme) {
        if (!this.running || this.resetting) throw new Error("Enable Qcord first.");
        if (scheme !== ACTIVE_SCHEME) throw new Error("Unknown key algorithm.");
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
                // Save the single supported key pair.
                config.save("key_pairs", {
                    [scheme]: {
                        public_key_spki_base64: keys.publicKey.export({type: "spki", format: "base64"}),
                        private_key_pkcs8_base64: keys.privateKey.export({type: "pkcs8", format: "base64"}),
                        created_at: keys.createdAt
                    }
                });
                config.save("config_version", 2);
                config.save("encrypt_outgoing_messages", Boolean(this.enabled));
                config.save("decrypt_incoming_messages", this.decodeIncoming !== false);
            }
            if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
            this.keyPairs.set(scheme, keys);
            this.keys = keys;
            this.schemeStatus[scheme] = "Bundled keygen passed";
            return keys;
        })();
        this.keyTasks.set(scheme, task);
        try { return await task; }
        catch (error) {
            if (this.session === session) this.schemeStatus[scheme] = error.message;
            throw error;
        }
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
        if (scheme !== ACTIVE_SCHEME) throw new Error("New recipients must use ML-KEM-512.");
        const partner = this.getDirectPartner(channelId);
        if (!Array.isArray(rows) || rows.length > 1) throw new Error("Save one public key for your DM partner.");
        const entries = rows.map(({user_id, public_key_spki_base64}) => {
            if (user_id !== partner.userId) throw new Error("The user ID must match this DM's recipient.");
            const key = PQC.createPublicKey(public_key_spki_base64);
            if (key.asymmetricKeyType !== scheme) throw new Error("Every recipient key must use the selected ML-KEM scheme.");
            return {channel_id: channelId, user_id, key_algorithm: scheme,
                public_key_spki_base64: key.export({type: "spki", format: "base64"}), saved_at: new Date().toISOString()};
        });
        config.save("dm_partners", [...this.getSavedPartners().filter(row => row.channel_id !== channelId), ...entries]);
    }

    removePartner(channelId) {
        if (this.resetting || !this.running) throw new Error("Enable Qcord first.");
        config.save("dm_partners", this.getSavedPartners().filter(row => row.channel_id !== channelId));
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

    wrappingKey(sharedSecret, version = 2) {
        return hkdf(sha256, bytes(sharedSecret), new Uint8Array(), new TextEncoder().encode(`Qcord v${version} key wrap`), 32);
    }

    packetHeader(channelId, fingerprints) {
        return {qcord_version: 2, kem_algorithm: ACTIVE_SCHEME, encryption_algorithm: "aes-256-gcm",
            key_derivation_algorithm: "hkdf-sha256", channel_id: channelId, recipient_key_fingerprints_sha256: fingerprints};
    }

    async encryptMessage(channelId, text) {
        if (!/^\d+$/.test(channelId || "")) throw new Error("Invalid channel.");
        const scheme = ACTIVE_SCHEME;
        const partner = this.getDirectPartner(channelId);
        const recipients = this.getRecipients(channelId, scheme);
        if (recipients.length !== 1 || recipients[0].user_id !== partner.userId) {
            throw new Error("Save your DM partner's ML-KEM-512 key in Qcord first.");
        }
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Message is too large for a Qcord file.");
        const session = this.session;
        const ownKeys = await this.generateKeys(scheme);
        const publicKeys = new Map();
        for (const key of [ownKeys.publicKey, ...recipients.map(row => PQC.createPublicKey(row.public_key_spki_base64))]) {
            if (key.asymmetricKeyType !== scheme) throw new Error("Recipient key algorithm does not match.");
            publicKeys.set(this.keyId(key), key);
        }
        const header = this.packetHeader(channelId, [...publicKeys.keys()]);
        const aad = Buffer.from(JSON.stringify(header));
        const payloadKey = randomBytes(32);
        const envelopes = [];
        for (const [id, publicKey] of publicKeys) {
            const {sharedKey, ciphertext} = await PQC.encapsulate(publicKey);
            envelopes.push({public_key_fingerprint_sha256: id, kem_ciphertext_base64: ciphertext.toString("base64"),
                wrapped_message_key: this.seal(payloadKey, this.wrappingKey(sharedKey), Buffer.concat([aad, Buffer.from(id)]))});
        }
        const output = JSON.stringify({...header, recipients: envelopes, encrypted_message: this.seal(input, payloadKey, aad)}, null, "\t") + "\n";
        const fileBytes = Buffer.byteLength(output);
        if (fileBytes > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file exceeds the 1 MiB display limit. Shorten your message.");
        if (!this.running || !this.enabled || this.session !== session) throw new Error("Qcord encryption was stopped.");
        return output;
    }

    async decryptMessage(text, channelId) {
        if (typeof text !== "string") return null;
        const legacy = text.startsWith(ENCRYPTED_PREFIX);
        if (!legacy && !text.trimStart().startsWith("{")) return null;
        if (Buffer.byteLength(text) > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file is too large.");
        const session = this.session;
        const file = JSON.parse(legacy ? text.slice(ENCRYPTED_PREFIX.length) : text);
        if (!legacy && file?.qcord_version !== 2) return null;
        const scheme = legacy ? file?.scheme : file?.kem_algorithm;
        if (!file || scheme !== ACTIVE_SCHEME || !/^\d+$/.test(channelId || "") || (legacy ? file.channelId : file.channel_id) !== channelId ||
            !Array.isArray(file.recipients) || !file.recipients.length || file.recipients.length > 2) throw new Error("Invalid encrypted file or wrong channel.");
        const ids = file.recipients.map(recipient => legacy ? recipient?.id : recipient?.public_key_fingerprint_sha256);
        if (ids.some(id => typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id)) || new Set(ids).size !== ids.length) throw new Error("Invalid recipient list.");
        const header = this.packetHeader(channelId, ids);
        if (!legacy && (file.encryption_algorithm !== header.encryption_algorithm || file.key_derivation_algorithm !== header.key_derivation_algorithm ||
            JSON.stringify(file.recipient_key_fingerprints_sha256) !== JSON.stringify(ids))) throw new Error("Invalid packet algorithms or fingerprints.");
        // Incoming files must never create new identities.
        if (!this.keyPairs.has(scheme) && !config.load("key_pairs")?.[scheme]) throw new Error("No saved private key for this file.");
        const keys = await this.generateKeys(scheme);
        const id = this.keyId(keys.publicKey);
        const recipient = file.recipients.find(entry => (legacy ? entry.id : entry.public_key_fingerprint_sha256) === id);
        if (!recipient) throw new Error("This file is not addressed to your key.");
        const aad = Buffer.from(JSON.stringify(legacy ? {scheme, channelId, recipientIds: ids} : header));
        const sharedKey = await PQC.decapsulate(keys.privateKey, this.decodeBytes(legacy ? recipient.kem : recipient.kem_ciphertext_base64, 768));
        const legacySeal = value => ({nonce_base64: value.iv, ciphertext_base64: value.data, authentication_tag_base64: value.tag});
        const payloadKey = this.openSealed(legacy ? legacySeal(recipient) : recipient.wrapped_message_key,
            this.wrappingKey(sharedKey, legacy ? 1 : 2), Buffer.concat([aad, Buffer.from(id)]));
        if (payloadKey.length !== 32) throw new Error("Invalid payload key.");
        const plaintext = this.openSealed(legacy ? legacySeal(file) : file.encrypted_message, payloadKey, aad);
        const decoded = new TextDecoder("utf-8", {fatal: true}).decode(plaintext);
        if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
        return decoded;
    }

    async testScheme(scheme, text) {
        const keys = await this.generateKeys(scheme);
        const session = this.session;
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Test input exceeds 1 MiB.");
        const encrypted = await PQC.encapsulate(keys.publicKey);
        const sharedKey = await PQC.decapsulate(keys.privateKey, encrypted.ciphertext);
        if (!equalBytes(bytes(encrypted.sharedKey), bytes(sharedKey))) throw new Error("KEM round-trip failed.");
        const aad = Buffer.from("Qcord v2 self-test");
        const sealed = this.seal(input, this.wrappingKey(encrypted.sharedKey), aad);
        if (!this.openSealed(sealed, this.wrappingKey(sharedKey), aad).equals(input)) throw new Error("Message round-trip failed.");
        const tag = Buffer.from(sealed.authentication_tag_base64, "base64");
        tag[0] ^= 1;
        let rejected = false;
        try { this.openSealed({...sealed, authentication_tag_base64: tag.toString("base64")}, this.wrappingKey(sharedKey), aad); }
        catch { rejected = true; }
        if (!rejected) throw new Error("Tamper detection failed.");
        if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
        this.schemeStatus[scheme] = "Key exchange, message round-trip and tamper rejection passed";
    }

};
