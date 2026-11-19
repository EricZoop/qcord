"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const {PQC} = require("../src/pqc");
const M = require("../src/mlkem");
const packet = require("../src/packet");
const message = require("../src/message");
const Encapsulation = require("../src/messaging");
const Qcord = require("../qcord.plugin.js");
const config = require("../src/config");
const {parameters} = require("../src/parameters");
const Ajv = require("ajv/dist/2020");
const ajv = new Ajv({allErrors: true});
const fileSchema = ajv.compile(JSON.parse(fs.readFileSync("schemas/qcord.schema.json", "utf8")));
const configSchema = ajv.compile(JSON.parse(fs.readFileSync("schemas/config.schema.json", "utf8")));
const scheme = "ml-kem-768", raw = key => Buffer.from(key.bytes).toString("base64");
let store = {}, channel = "100", staged = [];
let sent = [], unpatches = [];
const actions = {sendMessage: async (channelId, value) => {sent.push({channelId,value});return {shouldClear:true};},editMessage(){}};
global.document = {querySelectorAll: () => []};
global.BdApi = {
    Data: {load: (_, key) => structuredClone(store[key]), save: (_, key, value) => { store[key] = structuredClone(value); }, delete: (_, key) => { delete store[key]; }},
    Webpack: {getStore: name => ({ChannelStore: {getChannel: id => id === "300" ? {type: 3, recipients: ["2", "3"]} : {type: 1, recipients: ["2"]}}, SelectedChannelStore: {getChannelId: () => channel}})[name],
        getByKeys: key => key === "sendMessage" ? actions : key === "addFiles" ? {addFiles: async value => staged.push(value)} : null},
    Patcher:{instead:(_,object,key,callback)=>{const original=object[key];object[key]=function(...args){return callback(this,args,original);};const undo=()=>{object[key]=original;};unpatches.push(undo);return undo;},unpatchAll:()=>{unpatches.splice(0).reverse().forEach(undo=>undo());}},
    UI: {showToast() {}}
};
function client(Type = Encapsulation) { return Object.assign(new Type(), {running: true, session: {}, keyPairs: new Map(), keyTasks: new Map(), resets: new Set(), modeListeners:new Set(),pendingSends:new Map(),outgoingEpoch:{},autoEncrypt:false,autoDecrypt:true,attachments:{clear(){},retry(){},scan(){}},scheme}); }
function reset() { BdApi.Patcher.unpatchAll();store = {}; channel = "100"; staged = [];sent=[]; config.initialize(); }
async function pair(Type = Encapsulation) {
    reset(); const sender = client(Type), peer = await PQC.generateKeyPair(scheme);
    await sender.generateKeys();
    sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(peer.publicKey)}]);
    const receiver = client(); receiver.keyPairs.set(scheme, peer);
    return {sender, receiver, peer};
}
const flip = value => { const b = Buffer.from(value, "base64"); b[0] ^= 1; return b.toString("base64"); };

test("NTT and multiplication match independent negacyclic ring arithmetic", () => {
    const a = Array.from({length: 256}, (_, i) => (i * 71 + 19) % 3329), b = Array.from({length: 256}, (_, i) => (i * 11 + 2) % 3329), expected = Array(256).fill(0);
    assert.deepEqual(M.ntt(M.ntt(a), true), a);
    for (let i = 0; i < 256; i++) for (let j = 0; j < 256; j++) expected[(i + j) % 256] = M.mod(expected[(i + j) % 256] + (i + j >= 256 ? -1 : 1) * a[i] * b[j]);
    assert.deepEqual(M.ntt(M.multiply(M.ntt(a), M.ntt(b)), true), expected);
    for (let x = 0; x < 3329; x++) for (const d of [1, 4, 10]) assert.equal(M.compress(x, d), Math.round(2 ** d * x / 3329) % 2 ** d);
});

test("all three security levels round-trip keys, traces, packets and signature identities", async () => {
    reset();
    const sender = client();
    for (const level of ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]) {
        const keys = await sender.generateKeys(level), params = parameters(level);
        assert.equal(keys.publicKey.bytes.length, params.publicBytes);
        assert.ok(keys.publicSignature.length > 1000);
        assert.equal(PQC.validateSignatureKey(keys.publicSignature, level), keys.publicSignature);
        for (const [key, type] of [[keys.publicKey, "spki"], [keys.privateKey, "pkcs8"]]) {
            const imported = type === "spki" ? PQC.createPublicKey(key.export({type, format: "base64"})) : PQC.createPrivateKey(key.export({type, format: "base64"}));
            assert.ok(imported.equals(key));
        }
        sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(keys.publicKey), public_signature: keys.publicSignature}], level);
        let draft = await sender.prepareEncapsulation("100", undefined, "Initial draft");
        draft = sender.updateDraftMessage(draft, "Every level works");
        assert.equal(draft.scheme, level);
        assert.equal(draft.trace.u.length, params.k);
        assert.ok(fileSchema(draft.packet), JSON.stringify(fileSchema.errors));
        assert.equal((await sender.decapsulateFile(draft.wire)).text, "Every level works");
        await sender.saveDraft(draft);
        assert.equal((await sender.openFile(draft.wire, "100", draft.message_epoch)).text, "Every level works");
        assert.equal((await client().decapsulateFile(draft.wire)).text, "Every level works", "Identity survives reload");
    }
    assert.ok(configSchema(store), JSON.stringify(configSchema.errors));
    await assert.rejects(PQC.generateKeyPair("unknown"), /Unsupported/);
    assert.throws(() => PQC.validateSignatureKey("AAAA", scheme), /length/);
});

test("sender saved K and recipient dk decrypt the same single-envelope message, including exact Unicode", async () => {
    const {sender, receiver, peer} = await pair();
    const params = parameters();
    for (const text of ["Hello 👋\nα + β", "\uFEFFHello", "\uFEFF\uFEFF", "\0\r\n\uFFFD", " "]) {
        const draft = await sender.prepareEncapsulation("100", scheme, text), t = draft.trace;
        const c = packet.toCiphertext(draft.packet);
        assert.deepEqual(c, Buffer.from(t.ciphertext)); assert.equal(c.length, 1088);
        assert.deepEqual(draft.packet.kem.u, t.u.map(p => p.map(x => M.compress(x, params.du))));
        assert.deepEqual(draft.packet.kem.v, t.v.map(x => M.compress(x, params.dv)));
        assert.equal(t.aHat.length, 3); assert.equal(t.tHat.length, 3);
        assert.deepEqual(M.decapsulationTrace(peer.privateKey.bytes, c).m, t.m);
        const k = message.keyFromM(t.m, peer.publicKey.bytes);
        assert.deepEqual(await PQC.decapsulate(peer.privateKey, c), Buffer.from(k));
        const incoming = await receiver.decapsulateFile("\uFEFF" + draft.wire);
        assert.equal(incoming.text, text); assert.equal(incoming.key, Buffer.from(k).toString("hex"));
        await sender.saveDraft(draft); await sender.saveDraft(draft);
        const outgoing = await client().openFile(draft.wire, "100");
        assert.equal(outgoing.text, text); assert.equal(outgoing.key, incoming.key); assert.equal(outgoing.source, "Saved sender K");
        assert.ok(fileSchema(draft.packet), JSON.stringify(fileSchema.errors)); assert.ok(configSchema(store), JSON.stringify(configSchema.errors));
        assert.deepEqual(Object.keys(draft.packet).sort(), ["encrypted_message", "kem", "qcord_version", "signature_sigma"]);
        assert.ok(!draft.wire.includes(raw(peer.publicKey))); assert.ok(!draft.wire.includes(Buffer.from(t.m).toString("base64")));
        assert.equal(Buffer.from(draft.packet.encrypted_message.nonce_base64, "base64").length, 12);
        assert.equal(Buffer.from(draft.packet.encrypted_message.authentication_tag_base64, "base64").length, 16);
    }
    assert.equal(store.recipients[0].encapsulations.length, 5);
    await assert.rejects(sender.prepareEncapsulation("100", scheme, "bad\uD800"), /surrogate/);
});

test("editing text preserves u/v and m while refreshing the nonce; new encapsulations sample fresh m", async () => {
    const {sender, receiver} = await pair();
    const first = await sender.prepareEncapsulation("100", scheme, "First");
    const edited = sender.updateDraftMessage(first, "Edited");
    assert.deepEqual(edited.packet.kem.u, first.packet.kem.u); assert.deepEqual(edited.packet.kem.v, first.packet.kem.v); assert.deepEqual(edited.trace.m, first.trace.m);
    assert.notEqual(edited.packet.encrypted_message.nonce_base64, first.packet.encrypted_message.nonce_base64);
    assert.equal((await receiver.decapsulateFile(edited.wire)).text, "Edited");
    const second = await sender.prepareEncapsulation("100", scheme, "Edited");
    assert.notDeepEqual(second.trace.m, first.trace.m); assert.notDeepEqual(second.packet.kem.u, first.packet.kem.u);
    assert.equal(store.recipients[0].encapsulations.length, 0);
});

test("wrong keys and tampered u/v, nonce, ciphertext or tag fail message authentication", async () => {
    const {sender, receiver} = await pair();
    const draft = await sender.prepareEncapsulation("100", scheme, "Secret"); await sender.saveDraft(draft);
    for (const mutate of [p => p.kem.u[0][0] ^= 1, p => p.kem.v[0] ^= 1, p => p.encrypted_message.nonce_base64 = flip(p.encrypted_message.nonce_base64), p => p.encrypted_message.ciphertext_base64 = flip(p.encrypted_message.ciphertext_base64), p => p.encrypted_message.authentication_tag_base64 = flip(p.encrypted_message.authentication_tag_base64)]) {
        const changed = structuredClone(draft.packet); mutate(changed); const wire = JSON.stringify(changed);
        await assert.rejects(receiver.decapsulateFile(wire), /Could not decrypt/);
        if (JSON.stringify(changed.kem.u) === JSON.stringify(draft.packet.kem.u) && JSON.stringify(changed.kem.v) === JSON.stringify(draft.packet.kem.v)) await assert.rejects(sender.openFile(wire, "100"), /Could not decrypt/);
    }
    const wrong = client(); wrong.keyPairs.set(scheme, await PQC.generateKeyPair(scheme));
    await assert.rejects(wrong.decapsulateFile(draft.wire), /Could not decrypt/);
});

test("strict runtime parsing and JSON Schema agree on malformed files", () => {
    const valid = JSON.parse(fs.readFileSync("schemas/example.qcord", "utf8"));
    for (const mutate of [p => p.qcord_version = 4, p => p.parameter_set = "ml-kem-512", p => p.kem.u.splice(0, 2), p => p.kem.u[0].pop(), p => p.kem.v.pop(), p => p.kem.v[0] = 16, p => p.kem.u[0][0] = 1024, p => p.kem.v[0] = -1, p => p.kem.v[0] = 1.5, p => p.kem.v[0] = "1", p => p.m = "secret", p => delete p.encrypted_message, p => p.encrypted_message.nonce_base64 = "AA==", p => p.encrypted_message.authentication_tag_base64 = "AA==", p => p.encrypted_message.extra = 1, p => p.encrypted_message.ciphertext_base64 = "!bad"]) {
        const copy = structuredClone(valid); mutate(copy); assert.throws(() => packet.parse(JSON.stringify(copy))); assert.equal(fileSchema(copy), false);
    }
    assert.throws(() => packet.parse("x".repeat(1024 * 1024 + 1)), /too large/);
});

test("exact reviewed file is staged after K is saved; changed contacts, wrong DM and empty messages are blocked", async () => {
    const {sender} = await pair(Qcord);
    const draft = await sender.prepareEncapsulation("100", scheme, "Attach this");
    channel = "200"; await assert.rejects(sender.stageDraft(draft), /selected recipient/); channel = "100";
    await sender.stageDraft(draft); assert.equal(staged.length, 1); assert.equal(await staged[0].files[0].file.text(), draft.wire);
    assert.deepEqual(store.recipients[0].encapsulations[0], {message_epoch: draft.message_epoch, k: Buffer.from(message.keyFromM(draft.trace.m, PQC.createPublicKey(draft.public_encaps).bytes)).toString("base64")});
    assert.equal(staged[0].files[0].file.name, `${draft.message_epoch}.qcord`);
    const peer = await PQC.generateKeyPair(scheme); sender.saveRecipients("100", [{user_id: "2", public_encaps: raw(peer.publicKey)}]);
    assert.equal(store.recipients[0].encapsulations.length, 0); await assert.rejects(sender.stageDraft(draft), /key changed/);
    await assert.rejects(sender.prepareEncapsulation("300"), /one-to-one/);
    await assert.rejects(sender.saveDraft(await sender.prepareEncapsulation("100")), /Write a message/);
});

test("migration cleans a version-2 config with stale prefixed fields and retains only the current 768 identity", async () => {
    const current = await PQC.generateKeyPair(scheme), stale = await PQC.generateKeyPair(scheme);
    store = {config_version: 2, key_pairs: {[scheme]: {public_encaps: raw(current.publicKey), private_decaps: raw(current.privateKey)}, "ml-kem-512": {obsolete: true}},
        learning_config_version: 1, learning_key_pairs: {[scheme]: {public_key_spki_base64: stale.publicKey.export({type: "spki", format: "base64"}), private_key_pkcs8_base64: stale.privateKey.export({type: "pkcs8", format: "base64"})}},
        learning_parameter_set: "ml-kem-1024", learning_quantum_conversations: true, learning_dm_partners: [], dm_partners: [], recipients: [{channel_id: "100", user_id: "2", public_encaps: raw(stale.publicKey), encapsulations: []}], parameter_set: "ml-kem-768", encrypt_outgoing_messages: false, decrypt_incoming_messages: false};
    config.initialize();
    assert.deepEqual(Object.keys(store).sort(), ["auto_decrypt", "auto_encrypt", "auto_verify", "config_version", "key_sets", "recipients", "save_receipts"]);
    assert.equal(store.key_sets[scheme].public_encaps, raw(current.publicKey)); assert.equal(store.key_sets[scheme].private_decaps, raw(current.privateKey)); assert.equal(store.recipients.length, 1);
    assert.ok(configSchema(store), JSON.stringify(configSchema.errors));
    store.learning_key_pairs = {obsolete: true}; config.initialize(); assert.equal(store.learning_key_pairs, undefined);
});

test("clear config rotates the public/private pair, deletes contacts and m, invalidates pending work and survives reload", async () => {
    const {sender} = await pair(); const oldPublic = store.key_sets[scheme].public_encaps, oldPrivate = sender.keyPairs.get(scheme).privateKey.bytes;
    const draft = await sender.prepareEncapsulation("100", scheme, "Old text"); await sender.saveDraft(draft);
    const pending = sender.prepareEncapsulation("100", scheme, "Pending");
    const rejected = assert.rejects(pending, /stopped/);
    const resetting = sender.clearConfig();
    await assert.rejects(sender.prepareEncapsulation("100"), /stopped/);
    const fresh = await resetting; await rejected;
    assert.notEqual(store.key_sets[scheme].public_encaps, oldPublic); assert.equal(store.key_sets[scheme].public_encaps, raw(fresh.publicKey));
    assert.ok(oldPrivate.every(x => x === 0)); assert.deepEqual(store.recipients, []);
    assert.ok(PQC.createPublicKey(PQC.createPrivateKey(store.key_sets[scheme].private_decaps)).equals(PQC.createPublicKey(store.key_sets[scheme].public_encaps)));
    assert.equal(raw((await client().generateKeys()).publicKey), store.key_sets[scheme].public_encaps);
    await assert.rejects(sender.saveDraft(draft), /key changed/);
    assert.ok(configSchema(store), JSON.stringify(configSchema.errors));
});

test("both published example configs decrypt the complete example message", async () => {
    const sender = JSON.parse(fs.readFileSync("schemas/example.qcord.config.json", "utf8")), receiver = JSON.parse(fs.readFileSync("schemas/example.recipient.config.json", "utf8"));
    const wire = fs.readFileSync("schemas/example.qcord", "utf8");
    assert.ok(configSchema(sender), JSON.stringify(configSchema.errors)); assert.ok(configSchema(receiver), JSON.stringify(configSchema.errors));
    assert.ok(fileSchema(JSON.parse(wire)), JSON.stringify(fileSchema.errors));
    store = sender; const outgoing = await client().openFile(wire, "100");
    store = receiver; const incoming = await client().openFile(wire, "100");
    assert.equal(outgoing.text, "Hello from Qcord."); assert.equal(incoming.text, outgoing.text); assert.equal(incoming.key, outgoing.key);
});

test("vector rows round-trip without changing the ciphertext or authenticated message", () => {
    const file = JSON.parse(fs.readFileSync("schemas/example.qcord", "utf8"));
    const wire = packet.stringify(file), lines = wire.trimEnd().split("\n");
    const rows = lines.filter(line => /^      \[/.test(line));
    assert.equal(rows.length, 3);
    rows.forEach(line => assert.equal(JSON.parse(line.trim().replace(/,$/, "")).length, 256));
    const v = lines.find(line => line.startsWith('    "v": ['));
    assert.equal(JSON.parse(v.trim().slice(5).replace(/,$/, "")).length, 256);
    assert.deepEqual(packet.parse(wire).packet, file);
    assert.deepEqual(packet.aad(JSON.parse(wire)), packet.aad(file));
    assert.equal(wire, fs.readFileSync("schemas/example.qcord", "utf8"));
});

test("automatic encryption stages text without sending plaintext, while encryption and decryption toggle independently", async () => {
    const {sender}=await pair(Qcord);sender.installSendHook();
    sender.setAutomatic("decrypt",false);assert.equal(sender.autoDecrypt,false);assert.equal(sender.autoEncrypt,false);
    await actions.sendMessage("100",{content:"Normal text"});assert.equal(sent.length,1);assert.equal(staged.length,0);
    sender.setAutomatic("encrypt",true);assert.equal(sender.autoDecrypt,false);
    const result=await actions.sendMessage("100",{content:"Encrypted text"});assert.equal(result.shouldClear,true);assert.equal(sent.length,1);assert.equal(staged.length,1);
    const wire=await staged[0].files[0].file.text();assert.equal((await sender.openFile(wire,"100")).text,"Encrypted text");
    assert.ok(!wire.includes("Encrypted text"));
    await actions.sendMessage("100",{content:""});assert.equal(sent.length,2,"A second send submits the reviewed attachment");
    const failed=await actions.sendMessage("200",{content:"Keep this draft"});assert.equal(failed.shouldClear,false);assert.equal(sent.length,2);assert.equal(staged.length,1);
    sender.setAutomatic("decrypt",true);assert.equal(sender.autoEncrypt,true);
    assert.equal(store.auto_encrypt,true);assert.equal(store.auto_decrypt,true);
});

test("toggling encryption cancels pending sends, and decryption changes do not cancel outgoing encryption", async () => {
    const {sender}=await pair(Qcord);sender.installSendHook();sender.setAutomatic("encrypt",true);
    const pending=actions.sendMessage("100",{content:"Cancelled"});
    const duplicate=await actions.sendMessage("100",{content:"Cancelled"});assert.equal(duplicate.shouldClear,false);
    sender.setAutomatic("encrypt",false);sender.setAutomatic("encrypt",true);
    assert.equal((await pending).shouldClear,false);assert.equal(staged.length,0);assert.equal(sent.length,0);
    const next=actions.sendMessage("100",{content:"Keep encrypting"});sender.setAutomatic("decrypt",false);
    assert.equal((await next).shouldClear,true);assert.equal(staged.length,1);assert.equal(sent.length,0);
    assert.equal(sender.autoDecrypt,false);
});

test("an unavailable send hook cannot enable automatic encryption", async () => {
    const {sender}=await pair(Qcord);
    const patch=BdApi.Patcher.instead;
    try {
        BdApi.Patcher.instead=()=>{throw new Error("Unavailable API");};
        BdApi.Logger={warn(){}};
        sender.autoEncrypt=true;sender.installSendHook();
        assert.equal(sender.sendHookReady,false);assert.equal(sender.autoEncrypt,false);assert.equal(sender.autoDecrypt,true);
        assert.throws(()=>sender.setAutomatic("encrypt",true),/unavailable/);
    } finally {BdApi.Patcher.instead=patch;}
});


test("receipt preference skips new keys, preserves old receipts, and survives reload/reset", async () => {
    const {sender, receiver} = await pair(Qcord);
    const first = await sender.prepareEncapsulation("100", scheme, "Saved");
    await sender.stageDraft(first);
    sender.setSaveReceipts(false);
    const second = await sender.prepareEncapsulation("100", scheme, "Unsaved");
    await sender.stageDraft(second);
    assert.equal(store.save_receipts, false);
    assert.equal(store.recipients[0].encapsulations.length, 1);
    assert.equal((await sender.openFile(first.wire, "100", first.message_epoch)).text, "Saved");
    await assert.rejects(sender.openFile(second.wire, "100", second.message_epoch), /Could not decrypt/);
    assert.equal((await receiver.decapsulateFile(second.wire)).text, "Unsaved");
    config.initialize(); assert.equal(config.load("save_receipts"), false);
    assert.deepEqual(Object.keys(store), ["auto_encrypt", "auto_decrypt", "auto_verify", "save_receipts", "config_version", "key_sets", "recipients"]);
    sender.setSaveReceipts(true); await sender.stageDraft(second);
    assert.equal(store.recipients[0].encapsulations.length, 2);
    await sender.clearConfig(); assert.equal(sender.saveReceipts, true); assert.equal(store.save_receipts, true);
});

test("version-3 receipts migrate m to K without losing old messages or config order", async () => {
    const {sender} = await pair();
    const draft = await sender.prepareEncapsulation("100", scheme, "Legacy");
    store.config_version = 3;
    store.recipients[0].encapsulations = [{m: Buffer.from(draft.trace.m).toString("base64")}];
    config.initialize();
    assert.equal(store.config_version, 5);
    assert.equal(store.recipients[0].encapsulations[0].message_epoch, null);
    assert.equal(store.recipients[0].encapsulations[0].m, undefined);
    assert.ok(configSchema(store), JSON.stringify(configSchema.errors));
    assert.equal((await client().openFile(draft.wire, "100", 123)).text, "Legacy");
    assert.equal(Object.keys(store).at(-1), "recipients");
});

test("epoch receipt lookup caches its index and reopens directly without ML-KEM replay", async () => {
    const {sender} = await pair();
    const first = await sender.prepareEncapsulation("100", scheme, "First");
    await sender.saveDraft(first);
    const originalRestore = PQC.restoreEncapsulation;
    const originalGet = sender.getRecipients.bind(sender);
    let reads = 0;
    sender.getRecipients = (...args) => { reads++; return originalGet(...args); };
    PQC.restoreEncapsulation = () => { throw new Error("Sender replay must not re-encapsulate"); };
    try {
        for (let i = 0; i < 3; i++) assert.equal((await sender.openFile(first.wire, "100", first.message_epoch)).text, "First");
        assert.equal(reads, 1);
        await assert.rejects(sender.openFile(first.wire, "100", first.message_epoch + 1), /Could not decrypt/);
        sender.removePartner("100");
        await assert.rejects(sender.openFile(first.wire, "100", first.message_epoch), /Could not decrypt/);
        assert.equal(reads, 2);
    } finally { PQC.restoreEncapsulation = originalRestore; }
});


test("ML-DSA placeholders are blank, separate from ciphertext, and validated without changing legacy authentication", async () => {
    const {sender, receiver} = await pair();
    const draft = await sender.prepareEncapsulation("100", scheme, "Unsigned placeholder");
    assert.deepEqual(draft.packet.signature_sigma, {c_tilde: "", z: [], h: []});
    assert.ok(draft.wire.indexOf('"signature_sigma"') > draft.wire.indexOf('"encrypted_message"'));
    assert.ok(store.key_sets[scheme].public_signature); assert.ok(store.key_sets[scheme].private_signature);
    const legacy = structuredClone(draft.packet); delete legacy.signature_sigma;
    assert.ok(fileSchema(legacy), JSON.stringify(fileSchema.errors));
    assert.deepEqual(packet.aad(legacy), packet.aad(draft.packet));
    assert.equal((await receiver.decapsulateFile(packet.stringify(legacy))).text, "Unsigned placeholder");
    for (const sigma of [null, {}, {c: "", z: [], h: []}, {c_tilde: "AA==", z: [], h: []}, {c_tilde: "", z: [1], h: []}, {c_tilde: "", z: [], h: [1]}, {c_tilde: "", z: [], h: [], extra: ""}]) {
        const changed = {...draft.packet, signature_sigma: sigma};
        assert.equal(fileSchema(changed), false);
        assert.throws(() => packet.parse(JSON.stringify(changed)), /blank signature_sigma/);
        assert.throws(() => packet.stringify(changed), /blank signature_sigma/);
    }
    const changedConfig = {...store, public_signature: "unimplemented"};
    assert.equal(configSchema(changedConfig), false);
});

test("version-4 migration groups every level without changing identities, toggles or receipts", async () => {
    const {sender} = await pair();
    for (const level of ["ml-kem-512", "ml-kem-1024"]) await sender.generateKeys(level);
    const draft = await sender.prepareEncapsulation("100", scheme, "Retained receipt");
    await sender.saveDraft(draft);
    const before = structuredClone(store), sets = before.key_sets;
    store = {config_version: 4, auto_encrypt: true, auto_decrypt: false, auto_verify: true, save_receipts: false,
        public_encaps: sets[scheme].public_encaps, private_decaps: sets[scheme].private_decaps, public_signature: "", private_signature: "",
        security_keys: Object.fromEntries(["ml-kem-512", "ml-kem-1024"].map(level => [level, {public_encaps: sets[level].public_encaps, private_decaps: sets[level].private_decaps}])),
        signature_keys: Object.fromEntries(Object.entries(sets).map(([level, keys]) => [level, {public_signature: keys.public_signature, private_signature: keys.private_signature}])), recipients: before.recipients};
    config.initialize();
    assert.equal(store.config_version, 5);
    assert.deepEqual(store.key_sets, sets);
    assert.deepEqual(Object.keys(store).slice(0, 4), ["auto_encrypt", "auto_decrypt", "auto_verify", "save_receipts"]);
    for (const keys of Object.values(store.key_sets)) assert.deepEqual(Object.keys(keys), ["public_encaps", "private_decaps", "public_signature", "private_signature"]);
    assert.deepEqual([store.auto_encrypt, store.auto_decrypt, store.auto_verify, store.save_receipts], [true, false, true, false]);
    assert.ok(configSchema(store), JSON.stringify(configSchema.errors));
    const snapshot = structuredClone(store); config.initialize(); assert.deepEqual(store, snapshot);
    assert.equal((await client().openFile(draft.wire, "100", draft.message_epoch)).text, "Retained receipt");
    const oldSignature = store.key_sets[scheme].public_signature;
    await sender.clearConfig(); assert.notEqual(store.key_sets[scheme].public_signature, oldSignature);
});

test("legacy version-5 files still decrypt with their original authenticated structure", async () => {
    const {sender, receiver} = await pair();
    const draft = await sender.prepareEncapsulation("100", scheme, "Original file");
    const legacy = {qcord_version: 5, u: draft.packet.kem.u, v: draft.packet.kem.v};
    const key = message.keyFromM(draft.trace.m, PQC.createPublicKey(draft.public_encaps).bytes);
    try {
        legacy.encrypted_message = message.seal("Original file", key, legacy);
        assert.ok(fileSchema(legacy), JSON.stringify(fileSchema.errors));
        assert.equal((await receiver.decapsulateFile(packet.stringify(legacy))).text, "Original file");
        const moved = {qcord_version: 6, kem: {u: legacy.u, v: legacy.v}, encrypted_message: legacy.encrypted_message};
        await assert.rejects(receiver.decapsulateFile(packet.stringify(moved)), /Could not decrypt/, "Changing authenticated envelope without resealing fails");
        const mixed = {...draft.packet, u: legacy.u};
        assert.throws(() => packet.parse(JSON.stringify(mixed)), /Unexpected/);
        assert.equal(fileSchema(mixed), false);
    } finally { key.fill(0); }
});
