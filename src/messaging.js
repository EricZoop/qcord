"use strict";

const { Crypto, PQC } = require("./pqc");
const { KEY_STORE, SCHEMES, KEM_SCHEMES, ENCRYPTED_PREFIX, BASE64_RE, MAX_DECODED_FILE_SIZE } = require("./constants");

module.exports = class MessageCrypto {
    async generateKeys(scheme) {
        if (!this.running) throw new Error("Enable Qcord first.");
        if (!SCHEMES.includes(scheme)) throw new Error("Unknown key algorithm.");
        if (!Crypto?.randomBytes) throw new Error("This Discord runtime does not expose secure random bytes.");
        if (this.keyPairs.has(scheme)) return this.keyPairs.get(scheme);
        if (this.keyTasks.has(scheme)) return this.keyTasks.get(scheme);
        const session = this.session;
        const task = (async () => {
            const stored = BdApi.Data.load(KEY_STORE, "keyPairs") || {};
            if (typeof stored !== "object" || Array.isArray(stored)) throw new Error("Invalid saved key configuration.");
            let keys;
            if (stored[scheme]) {
                const {publicKey, privateKey, keygenMs} = stored[scheme];
                keys = {scheme, publicKey: PQC.createPublicKey(publicKey), privateKey: PQC.createPrivateKey(privateKey), keygenMs};
                if (keys.publicKey.asymmetricKeyType !== scheme || keys.privateKey.asymmetricKeyType !== scheme ||
                    !PQC.createPublicKey(keys.privateKey).equals(keys.publicKey)) {
                    throw new Error("Saved keys do not match. Restore your key configuration from backup.");
                }
            }
            else {
                const started = performance.now();
                keys = {scheme, ...await PQC.generateKeyPair(scheme), keygenMs: performance.now() - started};
                if (!this.running || this.session !== session) throw new Error("Qcord stopped during key generation.");
                // Reload so concurrent generation of different schemes preserves both.
                BdApi.Data.save(KEY_STORE, "keyPairs", {
                    ...(BdApi.Data.load(KEY_STORE, "keyPairs") || {}),
                    [scheme]: {
                        publicKey: keys.publicKey.export({type: "spki", format: "pem"}),
                        privateKey: keys.privateKey.export({type: "pkcs8", format: "pem"}),
                        keygenMs: keys.keygenMs, createdAt: new Date().toISOString()
                    }
                });
            }
            if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
            this.keyPairs.set(scheme, keys);
            this.keys = keys;
            this.schemeStatus[scheme] = "Bundled keygen passed";
            this.metrics.keygen = {scheme, ms: keys.keygenMs,
                publicBytes: keys.publicKey.export({type: "spki", format: "der"}).length,
                privateBytes: keys.privateKey.export({type: "pkcs8", format: "der"}).length};
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
        return Crypto.createHash("sha256").update(publicKey.export({type: "spki", format: "der"})).digest("hex");
    }

    saveRecipients(channelId, text, scheme) {
        if (!/^\d+$/.test(channelId || "")) throw new Error("Open a Discord channel first.");
        if (!KEM_SCHEMES.includes(scheme)) throw new Error("Choose an ML-KEM encryption scheme.");
        const pems = text.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g) || [];
        if (text.replace(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g, "").trim() || pems.length > 15) {
            throw new Error("Paste up to 15 public PEM keys, without other text.");
        }
        for (const pem of pems) {
            if (PQC.createPublicKey(pem).asymmetricKeyType !== scheme) throw new Error("Every recipient key must use the selected ML-KEM scheme.");
        }
        const recipients = BdApi.Data.load(KEY_STORE, "recipients") || {};
        BdApi.Data.save(KEY_STORE, "recipients", {...recipients, [channelId]: {scheme, publicKeys: pems}});
    }

    decodeBytes(value, size) {
        if (typeof value !== "string" || value.length > MAX_DECODED_FILE_SIZE || !BASE64_RE.test(value)) throw new Error("Invalid encrypted file field.");
        const bytes = Buffer.from(value, "base64");
        if (bytes.toString("base64") !== value || (size !== undefined && bytes.length !== size)) throw new Error("Invalid encrypted file field.");
        return bytes;
    }

    seal(data, key, aad) {
        const iv = Crypto.randomBytes(12);
        const cipher = Crypto.createCipheriv("aes-256-gcm", key, iv);
        cipher.setAAD(aad);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        return {iv: iv.toString("base64"), data: encrypted.toString("base64"), tag: cipher.getAuthTag().toString("base64")};
    }

    openSealed(sealed, key, aad) {
        const decipher = Crypto.createDecipheriv("aes-256-gcm", key, this.decodeBytes(sealed.iv, 12));
        decipher.setAAD(aad);
        decipher.setAuthTag(this.decodeBytes(sealed.tag, 16));
        return Buffer.concat([decipher.update(this.decodeBytes(sealed.data)), decipher.final()]);
    }

    wrappingKey(sharedSecret) {
        return Crypto.hkdfSync("sha256", sharedSecret, Buffer.alloc(0), Buffer.from("Qcord v2 key wrap"), 32);
    }

    async encryptMessage(channelId, text) {
        if (!Crypto?.createCipheriv || !Crypto?.hkdfSync) throw new Error("Discord must expose AES-GCM and HKDF support.");
        if (!/^\d+$/.test(channelId || "")) throw new Error("Invalid channel.");
        const scheme = this.scheme;
        const recipients = BdApi.Data.load(KEY_STORE, "recipients")?.[channelId];
        if (recipients?.scheme !== scheme || !Array.isArray(recipients.publicKeys) || !recipients.publicKeys.length) {
            throw new Error("Save recipient public keys for this channel and scheme in Qcord settings first.");
        }
        if (recipients.publicKeys.length > 15) throw new Error("At most 15 recipient keys are supported.");
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Message is too large for a Qcord file.");
        const session = this.session;
        const ownKeys = await this.generateKeys(scheme);
        const publicKeys = new Map();
        for (const key of [ownKeys.publicKey, ...recipients.publicKeys.map(pem => PQC.createPublicKey(pem))]) {
            if (key.asymmetricKeyType !== scheme) throw new Error("Recipient key algorithm does not match.");
            publicKeys.set(this.keyId(key), key);
        }
        const started = performance.now();
        const aad = Buffer.from(JSON.stringify({scheme, channelId, recipientIds: [...publicKeys.keys()]}));
        const payloadKey = Crypto.randomBytes(32);
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
        this.metrics.encrypt = {scheme, ms: performance.now() - started, inputBytes: input.length, fileBytes, recipients: envelopes.length};
        return output;
    }

    async decryptMessage(text, channelId) {
        if (!text.startsWith(ENCRYPTED_PREFIX)) return this.decodeText(text);
        if (!Crypto?.createDecipheriv || !Crypto?.hkdfSync) throw new Error("Discord must expose AES-GCM and HKDF support.");
        if (Buffer.byteLength(text) > MAX_DECODED_FILE_SIZE) throw new Error("Encrypted file is too large.");
        const started = performance.now();
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
        this.metrics.decrypt = {scheme: file.scheme, ms: performance.now() - started, inputBytes: plaintext.length, fileBytes: Buffer.byteLength(text)};
        return decoded;
    }

    async testScheme(scheme, text) {
        const keys = await this.generateKeys(scheme);
        const session = this.session;
        const input = Buffer.from(text, "utf8");
        if (input.length > MAX_DECODED_FILE_SIZE) throw new Error("Test input exceeds 1 MiB.");
        let started = performance.now();
        let result;
        if (KEM_SCHEMES.includes(scheme)) {
            const encrypted = await PQC.encapsulate(keys.publicKey);
            const encapsulateMs = performance.now() - started;
            started = performance.now();
            const sharedKey = await PQC.decapsulate(keys.privateKey, encrypted.ciphertext);
            if (!Crypto.timingSafeEqual(encrypted.sharedKey, sharedKey)) throw new Error("KEM round-trip failed.");
            result = {scheme, encapsulateMs, decapsulateMs: performance.now() - started, kemBytes: encrypted.ciphertext.length};
        }
        else {
            const signature = await PQC.sign(input, keys.privateKey);
            const signMs = performance.now() - started;
            started = performance.now();
            const valid = await PQC.verify(input, keys.publicKey, signature);
            if (!valid) throw new Error("Signature verification failed.");
            result = {scheme, signMs, verifyMs: performance.now() - started, inputBytes: input.length, signatureBytes: signature.length};
        }
        if (!this.running || this.session !== session) throw new Error("Qcord stopped.");
        this.schemeStatus[scheme] = "Round-trip passed";
        this.metrics.test = result;
        return result;
    }

};
