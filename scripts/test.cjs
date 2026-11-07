"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const {PQC} = require("../src/pqc");
const M = require("../src/mlkem");
const packet = require("../src/packet");
const Encapsulation = require("../src/messaging");
const Qcord = require("../qcord.plugin.js");
const config = require("../src/config");
const {PARAMETER_SETS} = require("../src/parameters");
const {sha3_256, sha3_512} = require("@noble/hashes/sha3.js");
const Ajv = require("ajv/dist/2020");
const validator = new Ajv({allErrors: true, strictTypes: false});
const fileSchema = validator.compile(JSON.parse(fs.readFileSync("schemas/qcord.schema.json", "utf8")));
const configSchema = validator.compile(JSON.parse(fs.readFileSync("schemas/config.schema.json", "utf8")));
let store = {}, channel = "100", staged = [];
const raw = key => Buffer.from(key.bytes).toString("base64");
global.document = {querySelectorAll: () => []};
global.BdApi = {
    Data: {load: (_, key) => structuredClone(store[key]), save: (_, key, value) => { store[key] = structuredClone(value); }, delete: (_, key) => { delete store[key]; }},
    Webpack: {getStore: name => ({ChannelStore: {getChannel: id => id === "300" ? {type: 3, recipients: ["2", "3"]} : {type: 1, recipients: ["2"]}}, SelectedChannelStore: {getChannelId: () => channel}})[name],
        getByKeys: key => key === "addFiles" ? {addFiles: async value => staged.push(value)} : null},
    UI: {showToast() {}}
};
function client(Type = Encapsulation) {
    return Object.assign(new Type(), {running: true, session: {}, keyPairs: new Map(), keyTasks: new Map(), scheme: "ml-kem-768"});
}
function reset() { store = {}; channel = "100"; staged = []; config.initialize(); }

test("NTT and multiplication match independent negacyclic ring arithmetic", () => {
    const a = Array.from({length: 256}, (_, i) => (i * 71 + 19) % 3329), b = Array.from({length: 256}, (_, i) => (i * 11 + 2) % 3329);
    assert.deepEqual(M.ntt(M.ntt(a), true), a);
    const expected = Array(256).fill(0);
    for (let i = 0; i < 256; i++) for (let j = 0; j < 256; j++) expected[(i + j) % 256] = M.mod(expected[(i + j) % 256] + (i + j >= 256 ? -1 : 1) * a[i] * b[j]);
    assert.deepEqual(M.ntt(M.multiply(M.ntt(a), M.ntt(b)), true), expected);
    assert.deepEqual(M.bits([65]), [1, 0, 0, 0, 0, 0, 1, 0]);
    for (let x = 0; x < 3329; x++) for (const d of [1, 4, 5, 10, 11]) assert.equal(M.compress(x, d), Math.round(2 ** d * x / 3329) % 2 ** d);
    assert.equal(M.decompress(1, 1), 1665);
});

for (const [scheme, params] of Object.entries(PARAMETER_SETS)) {
    test(`${scheme}: infer key, trace actual u/v, transmit, decapsulate, and reproduce sender K`, async () => {
        reset();
        const sender = client(), peer = await PQC.generateKeyPair(scheme);
        await sender.generateKeys(scheme);
        const inferred = PQC.createPublicKey(raw(peer.publicKey));
        assert.equal(inferred.asymmetricKeyType, scheme);
        assert.equal(inferred.bytes.length, params.publicBytes);
        assert.ok(PQC.createPublicKey(PQC.createPrivateKey(raw(peer.privateKey))).equals(inferred));
        // Existing DER keys are still importable.
        assert.ok(PQC.createPublicKey(peer.publicKey.export({type: "spki", format: "base64"})).equals(inferred));
        sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(peer.publicKey)}], scheme);
        const first = await sender.prepareEncapsulation("100", scheme), second = await sender.prepareEncapsulation("100", scheme);
        assert.notDeepEqual(first.trace.m, second.trace.m);
        assert.notEqual(first.wire, second.wire);
        assert.deepEqual(store.recipients[0].encapsulations, [], "Drafting does not persist m yet");
        const t = first.trace;
        assert.equal(t.tHat.length, params.k); assert.equal(t.aHat.length, params.k);
        assert.ok(t.aHat.every(row => row.length === params.k && row.every(p => p.length === 256)));
        const c = packet.toCiphertext(first.packet);
        assert.deepEqual(c, Buffer.from(t.ciphertext)); assert.equal(c.length, params.ciphertextBytes);
        assert.equal(first.packet.u.length, params.k); assert.equal(first.packet.v.length, 256);
        assert.deepEqual(first.packet.u, t.u.map(p => p.map(x => M.compress(x, params.du))));
        assert.deepEqual(first.packet.v, t.v.map(x => M.compress(x, params.dv)));
        assert.ok([...t.rVector].every(p => p.every(x => Math.abs(x) <= params.eta1)));
        assert.ok([...t.e1, t.e2].every(p => p.every(x => Math.abs(x) <= params.eta2)));
        assert.deepEqual(M.decapsulationTrace(peer.privateKey.bytes, c, scheme).m, t.m);
        const kr = sha3_512(Uint8Array.from([...t.m, ...sha3_256(peer.publicKey.bytes)]));
        const recovered = await PQC.decapsulate(peer.privateKey, c);
        assert.deepEqual(recovered, Buffer.from(kr.slice(0, 32)));
        const receiver = client(); receiver.keyPairs.set(scheme, peer);
        assert.equal((await receiver.decapsulateFile("\uFEFF" + first.wire)).key, recovered.toString("hex"));
        await sender.saveDraft(first); await sender.saveDraft(first); await sender.saveDraft(second);
        assert.equal(store.recipients[0].encapsulations.length, 2, "Retries don't duplicate saved m");
        const saved = store.recipients[0];
        assert.ok(configSchema(store), JSON.stringify(configSchema.errors));
        assert.ok(fileSchema(first.packet), JSON.stringify(fileSchema.errors));
        assert.deepEqual(Object.keys(saved).sort(), ["channel_id", "encapsulations", "public_encaps", "user_id"]);
        const restored = await PQC.restoreEncapsulation(PQC.createPublicKey(saved.public_encaps), Buffer.from(saved.encapsulations[0].m, "base64"));
        assert.deepEqual(restored.sharedKey, recovered); assert.deepEqual(restored.ciphertext, c);
        const reopened = await client().openFile(first.wire, "100");
        assert.equal(reopened.key, recovered.toString("hex")); assert.equal(reopened.source, "Saved sender m");
        assert.deepEqual(Object.keys(first.packet).sort(), ["parameter_set", "qcord_version", "u", "v"]);
        assert.ok(!first.wire.includes(saved.public_encaps)); assert.ok(!first.wire.includes(saved.encapsulations[0].m));
        const damaged = structuredClone(first.packet); damaged.u[0][0] ^= 1;
        assert.notDeepEqual(await PQC.decapsulate(peer.privateKey, packet.toCiphertext(damaged)), recovered);
        assert.equal((await receiver.decapsulateFile(JSON.stringify(damaged))).key.length, 64, "No implicit-rejection flag is exposed");
        const wrong = await PQC.generateKeyPair(scheme);
        assert.notDeepEqual(await PQC.decapsulate(wrong.privateKey, c), recovered);
        const badKey = Buffer.from(peer.publicKey.bytes); badKey[0] = 255; badKey[1] |= 15;
        assert.throws(() => PQC.createPublicKey(badKey.toString("base64")), /coefficient/);
        const broken = Uint8Array.from(c); broken[0] ^= 1;
        assert.throws(() => M.encapsulationTrace(peer.publicKey.bytes, t.m, broken, scheme), /did not match/);
    });
}

test("strict packet parsing rejects incorrect shapes, ranges, versions, extra fields and oversize files", async () => {
    const valid = JSON.parse(fs.readFileSync("schemas/example.qcord", "utf8"));
    for (const mutate of [p => p.qcord_version = 3, p => p.parameter_set = "ml-kem-512", p => p.parameter_set = "bad", p => p.u.pop(), p => p.u[0].pop(), p => p.v.pop(), p => p.v[0] = 16, p => p.u[0][0] = 1024, p => p.v[0] = -1, p => p.v[0] = 1.5, p => p.v[0] = "1", p => p.m = "secret", p => p.recipients = []]) {
        const copy = structuredClone(valid); mutate(copy); assert.throws(() => packet.parse(JSON.stringify(copy)));
        assert.equal(fileSchema(copy), false, "Schema and runtime reject the same malformed packet");
    }
    assert.throws(() => packet.parse("x".repeat(1024 * 1024 + 1)), /too large/);
    assert.throws(() => packet.parse("[]"));
    assert.throws(() => PQC.createPublicKey("not a public key"));
});

test("exact-file staging saves m first, allows ordinary captions, and rejects wrong DM or changed keys", async () => {
    reset(); const sender = client(Qcord), peer = await PQC.generateKeyPair("ml-kem-768");
    sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(peer.publicKey)}], "ml-kem-768");
    const draft = await sender.prepareEncapsulation("100");
    channel = "200"; await assert.rejects(sender.stageDraft(draft), /selected recipient/); channel = "100";
    await sender.stageDraft(draft);
    assert.equal(staged.length, 1); assert.equal(await staged[0].files[0].file.text(), draft.wire);
    assert.equal(store.recipients[0].encapsulations[0].m, Buffer.from(draft.trace.m).toString("base64"));
    const replacement = await PQC.generateKeyPair("ml-kem-768");
    sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(replacement.publicKey)}], "ml-kem-768");
    assert.deepEqual(store.recipients[0].encapsulations, []);
    await assert.rejects(sender.stageDraft(draft), /key changed/);
    await assert.rejects(sender.prepareEncapsulation("300"), /one-to-one/);
    const draft2 = await sender.prepareEncapsulation("100"); draft2.packet.v[0] ^= 1; draft2.wire = JSON.stringify(draft2.packet);
    await assert.rejects(sender.saveDraft(draft2), /no longer matches/);
});

test("stopped sessions cancel preparation and saving without persisting m", async () => {
    reset(); const sender = client(), peer = await PQC.generateKeyPair("ml-kem-768");
    sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(peer.publicKey)}], "ml-kem-768");
    const pending = sender.prepareEncapsulation("100"); sender.running = false;
    await assert.rejects(pending, /stopped/); assert.deepEqual(store.recipients[0].encapsulations, []);
    sender.running = true; const draft = await sender.prepareEncapsulation("100");
    const saving = sender.saveDraft(draft); sender.session = {};
    await assert.rejects(saving, /stopped/); assert.deepEqual(store.recipients[0].encapsulations, []);
});

test("concurrent parameter sets retain identities and contacts across switches and reloads", async () => {
    reset(); const sender = client(Qcord);
    await Promise.all(Object.keys(PARAMETER_SETS).map(s => sender.generateKeys(s)));
    const before = structuredClone(store.key_pairs);
    assert.equal(Object.keys(before).length, 3);
    for (const scheme of Object.keys(PARAMETER_SETS)) {
        const peer = await PQC.generateKeyPair(scheme);
        sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(peer.publicKey)}], scheme);
        sender.setScheme(scheme); assert.equal((await sender.prepareEncapsulation("100")).scheme, scheme);
        assert.deepEqual((await client().generateKeys(scheme)).publicKey.bytes, sender.keyPairs.get(scheme).publicKey.bytes);
    }
    assert.deepEqual(store.key_pairs, before); assert.equal(store.recipients.length, 3);
    sender.removePartner("100", "ml-kem-512"); assert.equal(store.recipients.length, 2);
});

test("one-time migration preserves identities and contacts and removes obsolete prefixed fields", async () => {
    const keys = await PQC.generateKeyPair("ml-kem-768"), pub = keys.publicKey.export({type: "spki", format: "base64"});
    store = {learning_config_version: 1, learning_key_pairs: {"ml-kem-768": {public_key_spki_base64: pub, private_key_pkcs8_base64: keys.privateKey.export({type: "pkcs8", format: "base64"})}}, learning_dm_partners: [{channel_id: "100", user_id: "2", key_algorithm: "ml-kem-768", public_key_spki_base64: pub}], learning_parameter_set: "ml-kem-768", learning_quantum_conversations: true};
    config.initialize();
    assert.equal(store.config_version, 2); assert.equal(store.key_pairs["ml-kem-768"].public_encaps, raw(keys.publicKey));
    assert.equal(store.recipients[0].public_encaps, raw(keys.publicKey));
    assert.ok(!Object.keys(store).some(key => key.startsWith("learning_")));
    const before = structuredClone(store); config.initialize(); assert.deepEqual(store, before);
    store.config_version = 99; assert.throws(() => config.initialize(), /Unsupported/);
});

test("published example configs reproduce and decapsulate the complete example attachment", async () => {
    const sender = JSON.parse(fs.readFileSync("schemas/example.qcord.config.json", "utf8"));
    const receiver = JSON.parse(fs.readFileSync("schemas/example.recipient.config.json", "utf8"));
    assert.ok(configSchema(sender), JSON.stringify(configSchema.errors));
    assert.ok(configSchema(receiver), JSON.stringify(configSchema.errors));
    const c = packet.parse(fs.readFileSync("schemas/example.qcord", "utf8")).ciphertext;
    const row = sender.recipients[0];
    const restored = await PQC.restoreEncapsulation(PQC.createPublicKey(row.public_encaps), Buffer.from(row.encapsulations[0].m, "base64"));
    assert.deepEqual(restored.ciphertext, c);
    assert.deepEqual(await PQC.decapsulate(PQC.createPrivateKey(receiver.key_pairs["ml-kem-768"].private_decaps), c), restored.sharedKey);
});

test("config schema rejects leaked wrapper fields, invalid m and mismatched key lengths", () => {
    const valid = JSON.parse(fs.readFileSync("schemas/example.qcord.config.json", "utf8"));
    for (const mutate of [p => p.learning_parameter_set = "ml-kem-768", p => p.recipients[0].encapsulations[0].m = "short", p => p.recipients[0].encapsulations[0].K = "unneeded", p => p.key_pairs["ml-kem-512"] = p.key_pairs["ml-kem-768"], p => p.recipients[0].public_encaps = "bad", p => p.recipients[0].channel_id = "bad"]) {
        const copy = structuredClone(valid); mutate(copy); assert.equal(configSchema(copy), false);
    }
});
