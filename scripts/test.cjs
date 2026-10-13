"use strict";

const {test} = require("node:test");
const assert = require("node:assert/strict");
const {gcm} = require("@noble/ciphers/aes.js");
const {hkdf} = require("@noble/hashes/hkdf.js");
const {sha256} = require("@noble/hashes/sha2.js");
const {PQC, randomBytes} = require("../src/pqc");
const MessageCrypto = require("../src/messaging");
const config = require("../src/config");
const panel = require("../src/settings");
const {ACTIVE_SCHEME, ENCRYPTED_PREFIX, MAX_DECODED_FILE_SIZE} = require("../src/constants");

let store = {};
const channels = new Map([
    ["100", {type: 1, recipients: ["2"]}],
    ["200", {type: 1, recipients: ["3"]}],
    ["300", {type: 3, recipients: ["2", "3"]}],
    ["400", {type: 0, recipients: []}]
]);
global.BdApi = {
    Data: {
        load: (name, key) => structuredClone(store[key]),
        save: (name, key, value) => { store[key] = structuredClone(value); },
        delete: (name, key) => { delete store[key]; }
    },
    Webpack: {getStore: name => ({
        ChannelStore: {getChannel: id => channels.get(id)},
        SelectedChannelStore: {getChannelId: () => "100"},
        UserStore: {getUser: id => ({id, username: "user" + id, globalName: "Contact " + id, avatar: "a_abcdef"})}
    })[name]}
};

function client(data = {}) {
    store = data;
    config.migrateConfiguration();
    return Object.assign(new MessageCrypto(), {running: true, enabled: true, decodeIncoming: true,
        session: {}, keyPairs: new Map(), keyTasks: new Map(), schemeStatus: {}});
}
const publicText = key => key.export({type: "spki", format: "base64"});
const privateText = key => key.export({type: "pkcs8", format: "base64"});
const keyConfig = keys => ({config_version: 2, key_pairs: {[ACTIVE_SCHEME]: {
    public_key_spki_base64: publicText(keys.publicKey), private_key_pkcs8_base64: privateText(keys.privateKey), created_at: "2026-01-01T00:00:00.000Z"
}}, dm_partners: []});

// Independently reproduce the released v1 wire format, including its old AAD and HKDF context.
async function legacyPacket(keys, channelId, text, id) {
    const aad = Buffer.from(JSON.stringify({scheme: ACTIVE_SCHEME, channelId, recipientIds: [id]}));
    const payloadKey = randomBytes(32);
    const {sharedKey, ciphertext} = await PQC.encapsulate(keys.publicKey);
    const wrapKey = hkdf(sha256, sharedKey, new Uint8Array(), Buffer.from("Qcord v1 key wrap"), 32);
    const seal = (input, key, associated) => {
        const nonce = randomBytes(12);
        const encrypted = Buffer.from(gcm(key, nonce, associated).encrypt(input));
        return {iv: Buffer.from(nonce).toString("base64"), data: encrypted.subarray(0, -16).toString("base64"), tag: encrypted.subarray(-16).toString("base64")};
    };
    return ENCRYPTED_PREFIX + JSON.stringify({scheme: ACTIVE_SCHEME, channelId,
        recipients: [{id, kem: ciphertext.toString("base64"), ...seal(payloadKey, wrapKey, Buffer.concat([aad, Buffer.from(id)]))}],
        ...seal(Buffer.from(text), payloadKey, aad)});
}

test("config migration keeps exact private/public keys and every DM binding", async () => {
    const keys = await PQC.generateKeyPair(ACTIVE_SCHEME);
    const data = {enabled: true, decodeIncoming: false, keyPairs: {[ACTIVE_SCHEME]: {
        publicKey: publicText(keys.publicKey), privateKey: privateText(keys.privateKey), createdAt: "2026-01-01T00:00:00.000Z"
    }}, recipients: {"100": {[ACTIVE_SCHEME]: [{userId: "2", publicKey: publicText(keys.publicKey)}]},
        "200": {[ACTIVE_SCHEME]: [{userId: "3", publicKey: publicText(keys.publicKey)}]}}};
    const plugin = client(data);
    assert.equal(data.key_pairs[ACTIVE_SCHEME].private_key_pkcs8_base64, privateText(keys.privateKey));
    assert.equal(data.key_pairs[ACTIVE_SCHEME].public_key_spki_base64, publicText(keys.publicKey));
    assert.equal(data.encrypt_outgoing_messages, true);
    assert.equal(data.decrypt_incoming_messages, false);
    assert.deepEqual(data.dm_partners.map(row => [row.channel_id, row.user_id]), [["100", "2"], ["200", "3"]]);
    assert.equal(data.keyPairs, undefined);
    assert.equal(data.recipients, undefined);
    const snapshot = structuredClone(data);
    config.migrateConfiguration();
    assert.deepEqual(data, snapshot);
    assert.equal(privateText((await plugin.generateKeys(ACTIVE_SCHEME)).privateKey), privateText(keys.privateKey));
    assert.equal(await plugin.decryptMessage(await legacyPacket(keys, "100", "Previous message", plugin.keyId(keys.publicKey)), "100"), "Previous message");
});

test("v2 packets are readable JSON and decrypt for sender and the correct contact", async () => {
    const senderKeys = await PQC.generateKeyPair(ACTIVE_SCHEME);
    const bobKeys = await PQC.generateKeyPair(ACTIVE_SCHEME);
    const carolKeys = await PQC.generateKeyPair(ACTIVE_SCHEME);
    const senderData = keyConfig(senderKeys);
    const sender = client(senderData);
    sender.saveRecipients("100", [{user_id: "2", public_key_spki_base64: publicText(bobKeys.publicKey)}], ACTIVE_SCHEME);
    sender.saveRecipients("200", [{user_id: "3", public_key_spki_base64: publicText(carolKeys.publicKey)}], ACTIVE_SCHEME);
    const text = "Educational packet: **hello** 👋\nSecond line";
    const wire = await sender.encryptMessage("100", text);
    const toCarol = await sender.encryptMessage("200", "For Carol");
    assert.ok(wire.startsWith('{\n\t"qcord_version"'));
    assert.ok(wire.endsWith("\n"));
    const packet = JSON.parse(wire);
    assert.equal(packet.channel_id, "100");
    assert.equal(packet.recipients.length, 2);
    assert.equal(Buffer.from(packet.recipients[0].kem_ciphertext_base64, "base64").length, 768);
    assert.equal(Buffer.from(packet.recipients[0].wrapped_message_key.ciphertext_base64, "base64").length, 32);
    assert.equal(Buffer.from(packet.encrypted_message.nonce_base64, "base64").length, 12);
    assert.equal(Buffer.from(packet.encrypted_message.authentication_tag_base64, "base64").length, 16);
    assert.equal(await sender.decryptMessage(wire, "100"), text);
    assert.notEqual(wire, await sender.encryptMessage("100", text));
    const bob = client(keyConfig(bobKeys));
    assert.equal(await bob.decryptMessage(wire, "100"), text);
    assert.equal(await bob.decryptMessage(JSON.stringify(packet), "100"), text);
    assert.equal(await bob.decryptMessage(JSON.stringify(Object.fromEntries(Object.entries(packet).reverse()), null, 2), "100"), text);
    await assert.rejects(bob.decryptMessage(toCarol, "200"), /not addressed/);
    const carol = client(keyConfig(carolKeys));
    assert.equal(await carol.decryptMessage(toCarol, "200"), "For Carol");
    await assert.rejects(carol.decryptMessage(wire, "100"), /not addressed/);
    store = senderData;
    sender.removePartner("100");
    assert.equal(sender.getSavedPartners().length, 1);
    assert.equal(await sender.decryptMessage(toCarol, "200"), "For Carol");
    await assert.rejects(sender.encryptMessage("100", "missing key"), /Save your DM partner/);
});

test("protected header, KEM, message key, ciphertext and tags reject tampering", async () => {
    const plugin = client();
    const own = await plugin.generateKeys(ACTIVE_SCHEME);
    plugin.saveRecipients("100", [{user_id: "2", public_key_spki_base64: publicText(own.publicKey)}], ACTIVE_SCHEME);
    const wire = await plugin.encryptMessage("100", "Secret");
    const flip = value => { const bytes = Buffer.from(value, "base64"); bytes[0] ^= 1; return bytes.toString("base64"); };
    const mutations = [
        p => { p.channel_id = "200"; },
        p => { p.kem_algorithm = "ml-kem-768"; },
        p => { p.encryption_algorithm = "aes-128-gcm"; },
        p => { p.key_derivation_algorithm = "none"; },
        p => { p.recipient_key_fingerprints_sha256[0] = "0".repeat(64); },
        p => { p.recipients[0].kem_ciphertext_base64 = flip(p.recipients[0].kem_ciphertext_base64); },
        p => { p.recipients[0].wrapped_message_key.ciphertext_base64 = flip(p.recipients[0].wrapped_message_key.ciphertext_base64); },
        p => { p.recipients[0].wrapped_message_key.authentication_tag_base64 = flip(p.recipients[0].wrapped_message_key.authentication_tag_base64); },
        p => { p.encrypted_message.ciphertext_base64 = flip(p.encrypted_message.ciphertext_base64); },
        p => { p.encrypted_message.nonce_base64 = flip(p.encrypted_message.nonce_base64); },
        p => { p.encrypted_message.authentication_tag_base64 = flip(p.encrypted_message.authentication_tag_base64); }
    ];
    for (const mutate of mutations) {
        const packet = JSON.parse(wire);
        mutate(packet);
        await assert.rejects(plugin.decryptMessage(JSON.stringify(packet), "100"));
    }
    await assert.rejects(plugin.decryptMessage(wire, "200"), /wrong channel/);
    await plugin.testScheme(ACTIVE_SCHEME, "Local check");
});

test("invalid recipients and unsupported channels cannot enable encrypted sending", async () => {
    const plugin = client();
    const keys = await plugin.generateKeys(ACTIVE_SCHEME);
    const row = {user_id: "2", public_key_spki_base64: publicText(keys.publicKey)};
    assert.throws(() => plugin.saveRecipients("300", [row], ACTIVE_SCHEME), /one-to-one/);
    assert.throws(() => plugin.saveRecipients("400", [row], ACTIVE_SCHEME), /one-to-one/);
    assert.throws(() => plugin.saveRecipients("100", [row, row], ACTIVE_SCHEME), /one public key/);
    assert.throws(() => plugin.saveRecipients("200", [row], ACTIVE_SCHEME), /must match/);
    assert.throws(() => plugin.saveRecipients("100", [{...row, public_key_spki_base64: "invalid"}], ACTIVE_SCHEME));
    await assert.rejects(plugin.encryptMessage("300", "secret"), /one-to-one/);
    plugin.saveRecipients("100", [row], ACTIVE_SCHEME);
    await assert.rejects(plugin.encryptMessage("100", "a".repeat(MAX_DECODED_FILE_SIZE)), /1 MiB/);
    await assert.rejects(plugin.decryptMessage("{" + " ".repeat(MAX_DECODED_FILE_SIZE), "100"), /too large/);
    plugin.enabled = false;
    await assert.rejects(plugin.encryptMessage("100", "secret"), /stopped/);
});

test("unknown config versions fail without modifying saved keys", () => {
    store = {config_version: 99, key_pairs: {secret: "preserve me"}};
    assert.throws(() => config.migrateConfiguration(), /Unsupported/);
    assert.deepEqual(store, {config_version: 99, key_pairs: {secret: "preserve me"}});
});

test("malformed legacy config is preserved and post-reset switch values survive startup", () => {
    store = {keyPairs: {"ml-kem-512": {publicKey: "incomplete"}}, enabled: true};
    const snapshot = structuredClone(store);
    assert.throws(() => config.migrateConfiguration(), /left unchanged/);
    assert.deepEqual(store, snapshot);
    store = {encrypt_outgoing_messages: true, decrypt_incoming_messages: false};
    config.migrateConfiguration();
    assert.equal(store.encrypt_outgoing_messages, true);
    assert.equal(store.decrypt_incoming_messages, false);
});

test("partner panel selects, edits and removes independent contacts and shows avatars", async () => {
    const plugin = client();
    const keys = await plugin.generateKeys(ACTIVE_SCHEME);
    plugin.saveRecipients("100", [{user_id: "2", public_key_spki_base64: publicText(keys.publicKey)}], ACTIVE_SCHEME);
    plugin.saveRecipients("200", [{user_id: "3", public_key_spki_base64: publicText(keys.publicKey)}], ACTIVE_SCHEME);
    const states = [];
    const effects = [];
    let cursor = 0;
    let initialized = false;
    BdApi.React = {
        createElement: (type, props, ...children) => ({type, props: props || {}, children: children.flat().filter(child => child !== null && child !== false && child !== undefined)}),
        useState: initial => {
            const index = cursor++;
            if (!(index in states)) states[index] = typeof initial === "function" ? initial() : initial;
            return [states[index], next => { states[index] = next; }];
        },
        useEffect: callback => { if (!initialized) effects.push(callback); }
    };
    const component = panel(plugin).type;
    const render = () => { cursor = 0; return component(); };
    render(); initialized = true;
    effects.forEach(effect => effect());
    await new Promise(resolve => setImmediate(resolve));
    const nodes = tree => [tree, ...tree.children.filter(child => typeof child === "object").flatMap(nodes)];
    const label = tree => typeof tree === "string" ? tree : (tree.children || []).map(label).join("");
    const findButton = (tree, text) => nodes(tree).find(node => node.type === "button" && label(node) === text);
    let tree = render();
    const cards = nodes(tree).filter(node => node.type === "button" && node.props.className?.includes("qcord-partner-card"));
    assert.equal(cards.length, 2);
    assert.ok(nodes(tree).some(node => node.type === "img" && node.props.src.includes("/avatars/2/")));
    cards[1].props.onClick(); tree = render();
    assert.ok(label(tree).includes("channel_id: 200"));
    assert.ok(label(tree).includes("user_id: 3"));
    const input = nodes(tree).find(node => node.type === "textarea" && !node.props.readOnly);
    input.props.onChange({target: {value: publicText(keys.publicKey)}}); tree = render();
    findButton(tree, "Replace key").props.onClick(); tree = render();
    assert.equal(plugin.getSavedPartners().length, 2);
    findButton(tree, "Remove partner").props.onClick(); tree = render();
    assert.equal(plugin.getSavedPartners().length, 1);
    assert.equal(plugin.getSavedPartners()[0].channel_id, "100");
    assert.ok(label(tree).includes("channel_id: 100"));
});
