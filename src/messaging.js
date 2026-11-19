"use strict";

const {PQC, equalBytes} = require("./pqc");
const config = require("./config");
const {parameters} = require("./parameters");
const DSA = require("./mldsa");
const packet = require("./packet");
const message = require("./message");
const {ACTIVE_SCHEME, MAX_DECODED_FILE_SIZE} = require("./constants");
const raw = key => Buffer.from(key.bytes).toString("base64");

module.exports = class Encapsulation {
    async generateKeys(scheme = ACTIVE_SCHEME) {
        if (!this.running || this.resetting) throw new Error("Enable Qcord and wait for reset to finish.");
        parameters(scheme);
        if (this.keyPairs.has(scheme)) return this.keyPairs.get(scheme);
        if (this.keyTasks.has(scheme)) return this.keyTasks.get(scheme);
        const session = this.session;
        const task = (async () => {
            const saved = config.load("key_sets")?.[scheme] || {};
            const publicEncaps = saved.public_encaps, privateDecaps = saved.private_decaps;
            let keys;
            if (publicEncaps || privateDecaps) {
                keys = {scheme, publicKey: PQC.createPublicKey(publicEncaps), privateKey: PQC.createPrivateKey(privateDecaps)};
                if (keys.publicKey.asymmetricKeyType !== scheme || keys.privateKey.asymmetricKeyType !== scheme || !PQC.createPublicKey(keys.privateKey).equals(keys.publicKey)) throw new Error("Saved public and private keys do not match.");
            } else {
                keys = {scheme, ...await PQC.generateKeyPair(scheme)};
                this.checkSession(session);
                config.saveKeySet(scheme, {public_encaps: raw(keys.publicKey), private_decaps: raw(keys.privateKey)});
            }
            this.checkSession(session);
            if (!saved.public_signature || !saved.private_signature) {
                const pair = await PQC.generateSignatureKeys(scheme);
                try {
                    this.checkSession(session);
                    config.saveKeySet(scheme, {public_signature: Buffer.from(pair.publicKey).toString("base64"), private_signature: Buffer.from(pair.privateKey).toString("base64")});
                } finally { pair.privateKey.fill(0); }
            }
            const identity = config.load("key_sets")[scheme];
            if (PQC.signaturePublicKey(identity.private_signature, scheme) !== identity.public_signature) throw new Error("Saved public and private signature keys do not match.");
            keys.publicSignature = identity.public_signature;
            keys.privateSignature = identity.private_signature;
            this.keyPairs.set(scheme, keys);
            return keys;
        })();
        this.keyTasks.set(scheme, task);
        try { return await task; }
        finally { if (this.keyTasks.get(scheme) === task) this.keyTasks.delete(scheme); }
    }

    checkSession(session) {
        if (!this.running || this.resetting || this.session !== session) throw new Error("Qcord was stopped or its keys changed.");
    }

    getSavedPartners() {
        const rows = config.load("recipients") || [];
        if (!Array.isArray(rows)) throw new Error("Invalid saved recipients.");
        return rows.map(row => ({...row, key_algorithm: PQC.createPublicKey(row.public_encaps).asymmetricKeyType}));
    }

    getRecipients(channelId, scheme) {
        if (scheme) parameters(scheme);
        return this.getSavedPartners().filter(row => row.channel_id === channelId && (!scheme || row.key_algorithm === scheme));
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
        if (channel?.type !== 1 || !Array.isArray(channel.recipients) || channel.recipients.length !== 1) throw new Error("Open a one-to-one DM to use Qcord.");
        const recipient = channel.recipients[0];
        const userId = typeof recipient === "string" ? recipient : recipient?.id;
        if (!/^\d{1,20}$/.test(userId || "")) throw new Error("Could not identify this DM's recipient.");
        return {userId, channelId};
    }

    saveRecipients(channelId, rows, scheme = ACTIVE_SCHEME) {
        this.checkSession(this.session);
        const partner = this.getDirectPartner(channelId);
        parameters(scheme);
        if (!Array.isArray(rows) || rows.length !== 1) throw new Error("Save one public key for your DM partner.");
        const {user_id, public_encaps, public_signature = ""} = rows[0];
        if (user_id !== partner.userId) throw new Error("The user ID must match this DM's recipient.");
        const key = PQC.createPublicKey(public_encaps);
        if (key.asymmetricKeyType !== scheme) throw new Error("The key does not match the selected ML-KEM parameter set.");
        const encoded = raw(key);
        const previous = this.getRecipients(channelId, scheme)[0];
        const entry = {channel_id: channelId, user_id, public_encaps: encoded, public_signature: public_signature ? PQC.validateSignatureKey(public_signature, scheme) : "",
            encapsulations: previous?.public_encaps === encoded ? previous.encapsulations : []};
        const saved = config.load("recipients") || [];
        const index = saved.findIndex(row => row.channel_id === channelId);
        if (index >= 0) saved[index] = entry;
        else saved.push(entry);
        config.save("recipients", saved);
        this.attachments?.clear(); this.scheduleMount?.();
    }

    removePartner(channelId, scheme = this.scheme || ACTIVE_SCHEME) {
        if (!this.running) throw new Error("Enable Qcord first.");
        config.save("recipients", (config.load("recipients") || []).filter(row => row.channel_id !== channelId || PQC.createPublicKey(row.public_encaps).asymmetricKeyType !== scheme));
        this.attachments?.clear(); this.scheduleMount?.();
    }

    async prepareEncapsulation(channelId, scheme, text = "") {
        scheme ||= this.getSavedPartners().find(row => row.channel_id === channelId)?.key_algorithm || ACTIVE_SCHEME;
        this.checkSession(this.session);
        const partner = this.getDirectPartner(channelId);
        const row = this.getRecipients(channelId, scheme)[0];
        if (!row || row.user_id !== partner.userId) throw new Error(`Save this recipient's ${parameters(scheme).label} public key first.`);
        const session = this.session;
        await this.generateKeys(scheme);
        this.checkSession(session);
        const result = await PQC.encapsulate(PQC.createPublicKey(row.public_encaps), true);
        try {
            this.checkSession(session);
            const file = packet.fromCiphertext(result.ciphertext, scheme);
            file.encrypted_message = message.seal(text, result.sharedKey, file);
            return this.serializeDraft({channelId, scheme, public_encaps: row.public_encaps, message_epoch: Date.now(), packet: file, trace: result.trace});
        } catch (error) { require("./mlkem").wipe(result.trace); throw error; }
        finally { result.sharedKey.fill(0); result.m.fill(0); }
    }

    serializeDraft(draft) {
        const identity = config.load("key_sets")?.[draft.scheme];
        if (!identity?.private_signature) throw new Error("Generate your signing identity before composing.");
        draft.packet.signature_sigma = DSA.decodeSignature(PQC.sign(packet.signaturePayload(draft.packet), identity.private_signature, draft.scheme), draft.scheme);
        const wire = packet.stringify(draft.packet);
        if (Buffer.byteLength(wire) > MAX_DECODED_FILE_SIZE) throw new Error("Qcord file exceeds 1 MiB. Shorten the message.");
        return {...draft, wire};
    }

    updateDraftMessage(draft, text) {
        this.checkSession(this.session);
        const key = message.keyFromM(draft.trace.m, PQC.createPublicKey(draft.public_encaps).bytes);
        try {
            const file = {...draft.packet};
            file.encrypted_message = message.seal(text, key, file);
            return this.serializeDraft({...draft, packet: file});
        } finally { key.fill(0); }
    }

    async saveDraft(draft) {
        const session = this.session;
        this.checkSession(session);
        const partner = this.getDirectPartner(draft.channelId);
        const rows = config.load("recipients") || [];
        const row = rows.find(r => r.channel_id === draft.channelId && r.public_encaps === draft.public_encaps && r.user_id === partner.userId);
        if (!row) throw new Error("The recipient key changed. Prepare a new draft.");
        const {ciphertext, packet: file} = packet.parse(draft.wire);
        parameters(draft.scheme);
        const restored = await PQC.restoreEncapsulation(PQC.createPublicKey(row.public_encaps), draft.trace.m);
        try {
            this.checkSession(session);
            if (!equalBytes(restored.ciphertext, ciphertext)) throw new Error("Draft no longer matches its m value.");
            const ownPublic = config.load("key_sets")?.[draft.scheme]?.public_signature;
            if (DSA.blank(file.signature_sigma) || !ownPublic || !PQC.verify(DSA.encodeSignature(file.signature_sigma, draft.scheme), packet.signaturePayload(file), ownPublic, draft.scheme)) throw new Error("Draft signature no longer matches your signing identity.");
            if (!message.open(file, restored.sharedKey).length) throw new Error("Write a message before attaching.");
            // Re-read after async work, preserving unrelated saves and detecting replacement.
            const current = config.load("recipients") || [];
            const target = current.find(r => r.channel_id === row.channel_id && r.public_encaps === row.public_encaps && r.user_id === row.user_id);
            if (!target) throw new Error("The recipient key changed. Prepare a new draft.");
            if (this.saveReceipts !== false) {
                const k = restored.sharedKey.toString("base64");
                target.encapsulations ||= [];
                if (!target.encapsulations.some(item => item.message_epoch === draft.message_epoch && item.k === k)) {
                    target.encapsulations.push({message_epoch: draft.message_epoch, k});
                }
                config.save("recipients", current);
            }
            this.attachments?.retry(); this.scheduleMount?.();
        } finally { restored.sharedKey.fill(0); }
    }

    async decapsulateFile(text) {
        const session = this.session;
        this.checkSession(session);
        const {packet: file, ciphertext} = packet.parse(text);
        const scheme = packet.schemeOf(file);
        if (!this.keyPairs.has(scheme) && !config.load("key_sets")?.[scheme]?.private_decaps) throw new Error("No saved decapsulation key.");
        const keys = await this.generateKeys(scheme);
        const sharedKey = await PQC.decapsulate(keys.privateKey, ciphertext);
        try {
            this.checkSession(session);
            // No validity flag: ML-KEM implicitly rejects invalid ciphertexts by returning a fallback key.
            return {scheme, key: sharedKey.toString("hex"), text: message.open(file, sharedKey)};
        } finally { sharedKey.fill(0); }
    }

    async openFile(text, channelId, messageEpoch = null, sender = {}) {
        this.checkSession(this.session);
        const {packet: file} = packet.parse(text);
        if (this.receiptRevision !== config.receiptsRevision || this.receiptSession !== this.session) {
            this.receiptSession = this.session;
            this.receiptIndexes = new Map();
            this.receiptRevision = config.receiptsRevision;
        }
        if (!this.receiptIndexes.has(channelId)) {
            const records = this.getRecipients(channelId).flatMap(row => row.encapsulations || []);
            const byEpoch = new Map();
            for (const record of records) {
                if (!byEpoch.has(record.message_epoch)) byEpoch.set(record.message_epoch, []);
                byEpoch.get(record.message_epoch).push(record);
            }
            this.receiptIndexes.set(channelId, {records, byEpoch});
        }
        const {records, byEpoch} = this.receiptIndexes.get(channelId);
        // Epoch filenames select current receipts; legacy/renamed files can try AES keys.
        const candidates = messageEpoch == null ? records : [...(byEpoch.get(messageEpoch) || []), ...(byEpoch.get(null) || [])];
        for (const record of candidates) {
            const key = packet.decodeBase64(record.k, 32);
            try {
                return this.withVerification({scheme: packet.schemeOf(file), key: key.toString("hex"), text: message.open(file, key), source: "Saved sender K"}, file, channelId, sender);
            } catch { /* Another receipt may share the filename epoch. */ }
            finally { key.fill(0); }
        }
        return this.withVerification({...await this.decapsulateFile(text), source: "Recipient dk"}, file, channelId, sender);
    }

    withVerification(result, file, channelId, sender = {}) {
        const opened = {...result, file, channelId, ...sender};
        opened.verification = this.verifyFileSignature(opened, this.autoVerify === true);
        opened.signatureStatus = opened.verification.status;
        return opened;
    }

    verifyFileSignature(result, verify = true, inspect = false) {
        this.checkSession(this.session);
        const {file, channelId, scheme} = result;
        const currentUserId = BdApi.Webpack.getStore?.("UserStore")?.getCurrentUser?.()?.id;
        const own = result.authorId ? result.authorId === currentUserId : result.source === "Saved sender K";
        const keySource = own ? "Your saved signing key" : "Contact's saved signing key";
        if (!verify) return {status: "unchecked", reason: "Signature has not been checked.", keySource};
        if (DSA.blank(file.signature_sigma)) return {status: "unsigned", reason: "This older file has no signature. Its sender cannot be verified.", keySource};
        if (result.requireAuthor && !result.authorId) return {status: "missing-author", reason: "Discord could not identify this message's author. No signature identity is assumed.", keySource};
        let publicKey;
        if (own) publicKey = config.load("key_sets")?.[scheme]?.public_signature;
        else {
            const partner = this.getDirectPartner(channelId);
            if (result.authorId && result.authorId !== partner.userId) return {status: "missing-author", reason: "Message author does not match this contact.", keySource};
            publicKey = this.getRecipients(channelId, scheme).find(row => row.user_id === partner.userId)?.public_signature;
        }
        if (!publicKey) return {status: "missing-key", reason: "Save the sender's public signature key in the recipient panel before verifying.", keySource};
        const payload = packet.signaturePayload(file), signature = DSA.encodeSignature(file.signature_sigma, scheme);
        const valid = PQC.verify(signature, payload, publicKey, scheme);
        const verification = {status: valid ? "verified" : "failed", reason: valid ? "Signature matches the saved public key and this encrypted envelope." : "Signature does not match the saved public key or this encrypted envelope.", keySource, publicKey, payloadBytes: payload.length, signatureBytes: signature.length};
        if (inspect) {
            verification.trace = DSA.verificationTrace(Buffer.from(publicKey, "base64"), payload, file.signature_sigma, scheme);
            const traceValid = verification.trace.computed === verification.trace.expected && verification.trace.zNorm < verification.trace.zBound && verification.trace.hintCount <= verification.trace.hintBound;
            if (valid !== traceValid) throw new Error("Verification walkthrough did not reproduce the library's result.");
        }
        return verification;
    }

    async clearConfig() {
        if (!this.running || this.resetting) throw new Error("Qcord is stopped or already resetting.");
        this.resetting = true;
        const session = this.session = {};
        this.attachments?.clear();
        for (const pair of this.keyPairs.values()) pair.privateKey.bytes.fill(0);
        this.keyPairs.clear(); this.keyTasks.clear();
        this.receiptIndexes?.clear();
        let keys;
        try {
            keys = {scheme: ACTIVE_SCHEME, ...await PQC.generateKeyPair(ACTIVE_SCHEME)};
            if (!this.running || this.session !== session) throw new Error("Qcord stopped during reset.");
            config.reset(keys);

            this.autoVerify = false; this.autoEncrypt = false; this.autoDecrypt = true; this.saveReceipts = true; this.outgoingEpoch = {};
            this.resetting = false;
            keys.privateKey.bytes.fill(0);
            keys = await this.generateKeys(ACTIVE_SCHEME);
            this.mountButtons?.();
            for (const notify of this.modeListeners || []) notify();
            for (const reset of this.resets || []) reset(keys);
            this.scheduleMount?.();
            return keys;
        } catch (error) { keys?.privateKey.bytes.fill(0); throw error; }
        finally { if (this.session === session) this.resetting = false; }
    }
};
