"use strict";

const {PQC, equalBytes} = require("./pqc");
const config = require("./config");
const {parameters} = require("./parameters");
const packet = require("./packet");
const {ACTIVE_SCHEME} = require("./constants");
const raw = key => Buffer.from(key.bytes).toString("base64");

module.exports = class Encapsulation {
    async generateKeys(scheme) {
        if (!this.running) throw new Error("Enable Qcord first.");
        parameters(scheme);
        if (this.keyPairs.has(scheme)) return this.keyPairs.get(scheme);
        if (this.keyTasks.has(scheme)) return this.keyTasks.get(scheme);
        const session = this.session;
        const task = (async () => {
            const stored = config.load("key_pairs") || {};
            let keys;
            if (stored[scheme]) {
                keys = {scheme, publicKey: PQC.createPublicKey(stored[scheme].public_encaps), privateKey: PQC.createPrivateKey(stored[scheme].private_decaps)};
                if (keys.publicKey.asymmetricKeyType !== scheme || keys.privateKey.asymmetricKeyType !== scheme || !PQC.createPublicKey(keys.privateKey).equals(keys.publicKey)) throw new Error("Saved public and private keys do not match.");
            } else {
                keys = {scheme, ...await PQC.generateKeyPair(scheme)};
                this.checkSession(session);
                config.save("key_pairs", {...config.load("key_pairs"), [scheme]: {public_encaps: raw(keys.publicKey), private_decaps: raw(keys.privateKey)}});
            }
            this.checkSession(session);
            this.keyPairs.set(scheme, keys);
            return keys;
        })();
        this.keyTasks.set(scheme, task);
        try { return await task; }
        finally { if (this.keyTasks.get(scheme) === task) this.keyTasks.delete(scheme); }
    }

    checkSession(session) {
        if (!this.running || this.session !== session) throw new Error("Qcord was stopped or its keys changed.");
    }

    getSavedPartners() {
        const rows = config.load("recipients") || [];
        if (!Array.isArray(rows)) throw new Error("Invalid saved recipients.");
        return rows.map(row => ({...row, key_algorithm: PQC.createPublicKey(row.public_encaps).asymmetricKeyType}));
    }

    getRecipients(channelId, scheme) {
        return this.getSavedPartners().filter(row => row.channel_id === channelId && row.key_algorithm === scheme);
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

    saveRecipients(channelId, rows, scheme) {
        if (!this.running) throw new Error("Enable Qcord first.");
        const partner = this.getDirectPartner(channelId);
        parameters(scheme);
        if (!Array.isArray(rows) || rows.length !== 1) throw new Error("Save one public key for your DM partner.");
        const {user_id, public_encaps} = rows[0];
        if (user_id !== partner.userId) throw new Error("The user ID must match this DM's recipient.");
        const key = PQC.createPublicKey(public_encaps);
        if (key.asymmetricKeyType !== scheme) throw new Error("The key does not match the selected ML-KEM parameter set.");
        const encoded = raw(key);
        const previous = this.getRecipients(channelId, scheme)[0];
        const entry = {channel_id: channelId, user_id, public_encaps: encoded,
            encapsulations: previous?.public_encaps === encoded ? previous.encapsulations : []};
        const others = (config.load("recipients") || []).filter(row => row.channel_id !== channelId || PQC.createPublicKey(row.public_encaps).asymmetricKeyType !== scheme);
        config.save("recipients", [...others, entry]);
    }

    removePartner(channelId, scheme = this.scheme || ACTIVE_SCHEME) {
        if (!this.running) throw new Error("Enable Qcord first.");
        config.save("recipients", (config.load("recipients") || []).filter(row => row.channel_id !== channelId || PQC.createPublicKey(row.public_encaps).asymmetricKeyType !== scheme));
    }

    async prepareEncapsulation(channelId, scheme = this.scheme || ACTIVE_SCHEME) {
        const partner = this.getDirectPartner(channelId);
        const row = this.getRecipients(channelId, scheme)[0];
        if (!row || row.user_id !== partner.userId) throw new Error(`Save this recipient's ${parameters(scheme).label} public key first.`);
        const session = this.session;
        const result = await PQC.encapsulate(PQC.createPublicKey(row.public_encaps), true);
        try {
            this.checkSession(session);
            const file = packet.fromCiphertext(result.ciphertext, scheme);
            return {channelId, scheme, public_encaps: row.public_encaps, packet: file,
                wire: JSON.stringify(file, null, 2) + "\n", trace: result.trace};
        } catch (error) { require("./mlkem").wipe(result.trace); throw error; }
        finally { result.sharedKey.fill(0); result.m.fill(0); }
    }

    async saveDraft(draft) {
        const session = this.session;
        this.checkSession(session);
        const partner = this.getDirectPartner(draft.channelId);
        const rows = config.load("recipients") || [];
        const row = rows.find(r => r.channel_id === draft.channelId && r.public_encaps === draft.public_encaps && r.user_id === partner.userId);
        if (!row) throw new Error("The recipient key changed. Prepare a new draft.");
        const {ciphertext, packet: file} = packet.parse(draft.wire);
        if (file.parameter_set !== draft.scheme) throw new Error("Draft parameter set changed.");
        const restored = await PQC.restoreEncapsulation(PQC.createPublicKey(row.public_encaps), draft.trace.m);
        try {
            this.checkSession(session);
            if (!equalBytes(restored.ciphertext, ciphertext)) throw new Error("Draft no longer matches its m value.");
            // Re-read after async work, preserving unrelated saves and detecting replacement.
            const current = config.load("recipients") || [];
            const target = current.find(r => r.channel_id === row.channel_id && r.public_encaps === row.public_encaps && r.user_id === row.user_id);
            if (!target) throw new Error("The recipient key changed. Prepare a new draft.");
            const m = Buffer.from(draft.trace.m).toString("base64");
            target.encapsulations ||= [];
            if (!target.encapsulations.some(item => item.m === m)) target.encapsulations.push({m});
            config.save("recipients", current);
        } finally { restored.sharedKey.fill(0); }
    }

    async decapsulateFile(text) {
        const session = this.session;
        this.checkSession(session);
        const {packet: file, ciphertext} = packet.parse(text);
        const scheme = file.parameter_set;
        if (!this.keyPairs.has(scheme) && !config.load("key_pairs")?.[scheme]) throw new Error("No saved decapsulation key for this parameter set.");
        const keys = await this.generateKeys(scheme);
        const sharedKey = await PQC.decapsulate(keys.privateKey, ciphertext);
        try {
            this.checkSession(session);
            // No validity flag: ML-KEM implicitly rejects invalid ciphertexts by returning a fallback key.
            return {scheme, key: sharedKey.toString("hex")};
        } finally { sharedKey.fill(0); }
    }

    async openFile(text, channelId) {
        const session = this.session;
        this.checkSession(session);
        const {packet: file, ciphertext} = packet.parse(text);
        // Sender replay needs only the saved recipient key and each original m.
        // No key fingerprint or duplicate ciphertext is stored in the config.
        for (const row of this.getRecipients(channelId, file.parameter_set)) {
            const key = PQC.createPublicKey(row.public_encaps);
            for (const record of row.encapsulations || []) {
                const m = Buffer.from(record.m, "base64");
                let restored;
                try {
                    if (m.toString("base64") !== record.m || m.length !== 32) throw new Error("Invalid saved m.");
                    restored = await PQC.restoreEncapsulation(key, m);
                    this.checkSession(session);
                    if (equalBytes(restored.ciphertext, ciphertext)) return {scheme: file.parameter_set, key: restored.sharedKey.toString("hex"), source: "Saved sender m"};
                } finally { m.fill(0); restored?.sharedKey.fill(0); }
            }
        }
        return {...await this.decapsulateFile(text), source: "Recipient dk"};
    }
};
