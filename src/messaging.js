"use strict";

const {PQC, randomBytes, equalBytes} = require("./pqc");
const {gcm} = require("@noble/ciphers/aes.js");
const {sha256} = require("@noble/hashes/sha2.js");
const {hkdf} = require("@noble/hashes/hkdf.js");
const bytes = value => Uint8Array.from(value);
const { KEY_STORE, SCHEMES, KEM_SCHEMES, ENCRYPTED_PREFIX, BASE64_RE, MAX_DECODED_FILE_SIZE } = require("./constants");

module.exports = class MessageCrypto {
    async generateKeys(scheme) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (!SCHEMES.includes(scheme)) throw new Error("Unknown key algorithm.");
        if (this.keyPairs.has(scheme)) return this.keyPairs.get(scheme);
        if (this.keyTasks.has(scheme)) return this.keyTasks.get(scheme);
        const session = this.session;
        const task = (async () => {
            const stored = BdApi.Data.load(KEY_STORE, "keyPairs") || {};
            if (typeof stored !== "object" || Array.isArray(stored)) throw new Error("Invalid saved key configuration.");
            let keys;
            if (stored[scheme]) {
                const {publicKey, privateKey} = stored[scheme];
                keys = {scheme, publicKey: PQC.createPublicKey(publicKey), privateKey: PQC.createPrivateKey(privateKey)};
                if (keys.publicKey.asymmetricKeyType !== scheme || keys.privateKey.asymmetricKeyType !== scheme ||
                    !PQC.createPublicKey(keys.privateKey).equals(keys.publicKey)) {
                    throw new Error("Saved keys do not match. Restore your key configuration from backup.");
                }
            }
            else {
                keys = {scheme, ...await PQC.generateKeyPair(scheme)};
                if (!this.running || this.session !== session) throw new Error("Qcord stopped during key generation.");
                // Reload so concurrent generation of different schemes preserves both.
                BdApi.Data.save(KEY_STORE, "keyPairs", {
                    ...(BdApi.Data.load(KEY_STORE, "keyPairs") || {}),
                    [scheme]: {
                        publicKey: keys.publicKey.export({type: "spki", format: "pem"}),
                        privateKey: keys.privateKey.export({type: "pkcs8", format: "pem"}),
                        createdAt: new Date().toISOString()
                    }
                });
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
        const saved = BdApi.Data.load(KEY_STORE, "recipients")?.[channelId];
        // Read existing recipient keys without replacing the user's saved configuration.
        if (saved?.scheme === scheme) return saved.publicKeys.map(publicKey => ({username: "", publicKey}));
        return saved?.[scheme] || [];
    }

    saveRecipients(channelId, rows, scheme) {
        if (!/^\d+$/.test(channelId || "")) throw new Error("Open a Discord channel first.");
        if (!KEM_SCHEMES.includes(scheme)) throw new Error("Choose an ML-KEM encryption scheme.");
        if (!Array.isArray(rows) || rows.length > 15) throw new Error("Add up to 15 recipients.");
        const seen = new Set();
        const entries = rows.map(({username, publicKey}) => {
            if (typeof username !== "string" || username.length > 100) throw new Error("Use a recipient name of up to 100 characters.");
            const key = PQC.createPublicKey(publicKey);
            if (key.asymmetricKeyType !== scheme) throw new Error("Every recipient key must use the selected ML-KEM scheme.");
            const id = this.keyId(key);
            if (seen.has(id)) throw new Error("That public key is already in the recipient table.");
            seen.add(id);
            return {username: username.trim(), publicKey: key.export({type: "spki", format: "pem"})};
        });
        const recipients = BdApi.Data.load(KEY_STORE, "recipients") || {};
        const previous = recipients[channelId];
        const channel = previous?.scheme ? {[previous.scheme]: this.getRecipients(channelId, previous.scheme)} : previous || {};
        BdApi.Data.save(KEY_STORE, "recipients", {...recipients, [channelId]: {...channel, [scheme]: entries}});
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
        return {iv: Buffer.from(iv).toString("base64"), data: sealed.subarray(0, -16).toString("base64"), tag: sealed.subarray(-16).toString("base64")};
    }

    openSealed(sealed, key, aad) {
        const iv = bytes(this.decodeBytes(sealed.iv, 12));
        const ciphertext = Buffer.concat([this.decodeBytes(sealed.data), this.decodeBytes(sealed.tag, 16)]);
        return Buffer.from(gcm(bytes(key), iv, bytes(aad)).decrypt(bytes(ciphertext)));
    }

    wrappingKey(sharedSecret) {
        return hkdf(sha256, bytes(sharedSecret), new Uint8Array(), new TextEncoder().encode("Qcord v2 key wrap"), 32);
    }

    async encryptMessage(channelId, text) {
        if (!/^\d+$/.test(channelId || "")) throw new Error("Invalid channel.");
        const scheme = this.scheme;
        const recipients = this.getRecipients(channelId, scheme);
        if (!Array.isArray(recipients) || !recipients.length) {
            throw new Error("Save recipient public keys for this channel and scheme in Qcord settings first.");
        }
        if (recipients.length > 15) throw new Error("At most 15 recipient keys are supported.");
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Message is too large for a Qcord file.");
        const session = this.session;
        const ownKeys = await this.generateKeys(scheme);
        const publicKeys = new Map();
        for (const key of [ownKeys.publicKey, ...recipients.map(row => PQC.createPublicKey(row.publicKey))]) {
            if (key.asymmetricKeyType !== scheme) throw new Error("Recipient key algorithm does not match.");
            publicKeys.set(this.keyId(key), key);
        }
        const aad = Buffer.from(JSON.stringify({scheme, channelId, recipientIds: [...publicKeys.keys()]}));
        const payloadKey = randomBytes(32);
        const envelopes = [];
        for (const [id, publicKey] of publicKeys) {
            const {sharedKey, ciphertext} = await PQC.encapsulate(publicKey);
            envelopes.push({id, kem: ciphertext.toString("base64"),
                ...this.seal(payloadKey, this.wrappingKey(sharedKey), Buffer.concat([aad, Buffer.from(id)]))});
        }
        const output = ENCRYPTED_PREFIX + JSON.stringify({scheme, channelId, recipients: envelopes, ...this.seal(input, payloadKey, aad)});
        const fileBytes = Buffer.byteLength(output);
        if (fileBytes > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file exceeds the 1 MiB display limit. Shorten your message.");
        if (!this.running || !this.enabled || this.session !== session) throw new Error("Qcord encryption was stopped.");
        return output;
    }

    async decryptMessage(text, channelId) {
        if (typeof text !== "string" || !text.startsWith(ENCRYPTED_PREFIX)) return null;
        if (Buffer.byteLength(text) > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file is too large.");
        const session = this.session;
        const file = JSON.parse(text.slice(ENCRYPTED_PREFIX.length));
        if (!file || !KEM_SCHEMES.includes(file.scheme) || !/^\d+$/.test(channelId || "") || file.channelId !== channelId ||
            !Array.isArray(file.recipients) || !file.recipients.length || file.recipients.length > 16) throw new Error("Invalid encrypted file or wrong channel.");
        const ids = file.recipients.map(recipient => recipient?.id);
        if (ids.some(id => typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id)) || new Set(ids).size !== ids.length) throw new Error("Invalid recipient list.");
        // Incoming files must never create new identities.
        if (!this.keyPairs.has(file.scheme) && !BdApi.Data.load(KEY_STORE, "keyPairs")?.[file.scheme]) throw new Error("No saved private key for this file.");
        const keys = await this.generateKeys(file.scheme);
        const id = this.keyId(keys.publicKey);
        const recipient = file.recipients.find(entry => entry.id === id);
        if (!recipient) throw new Error("This file is not addressed to your key.");
        const aad = Buffer.from(JSON.stringify({scheme: file.scheme, channelId, recipientIds: ids}));
        const sharedKey = await PQC.decapsulate(keys.privateKey, this.decodeBytes(recipient.kem));
        const payloadKey = this.openSealed(recipient, this.wrappingKey(sharedKey), Buffer.concat([aad, Buffer.from(id)]));
        if (payloadKey.length !== 32) throw new Error("Invalid payload key.");
        const plaintext = this.openSealed(file, payloadKey, aad);
        const decoded = new TextDecoder("utf-8", {fatal: true}).decode(plaintext);
        if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
        return decoded;
    }

    async testScheme(scheme, text) {
        const keys = await this.generateKeys(scheme);
        const session = this.session;
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Test input exceeds 1 MiB.");
        if (KEM_SCHEMES.includes(scheme)) {
            const encrypted = await PQC.encapsulate(keys.publicKey);
            const sharedKey = await PQC.decapsulate(keys.privateKey, encrypted.ciphertext);
            if (!equalBytes(bytes(encrypted.sharedKey), bytes(sharedKey))) throw new Error("KEM round-trip failed.");
        }
        else {
            const signature = await PQC.sign(input, keys.privateKey);
            const valid = await PQC.verify(input, keys.publicKey, signature);
            if (!valid) throw new Error("Signature verification failed.");
        }
        if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
        this.schemeStatus[scheme] = "Round-trip passed";
    }

};
