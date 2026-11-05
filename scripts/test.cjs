"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const {PQC} = require("../src/pqc");
const L = require("../src/learning");
const MessageCrypto = require("../src/messaging");
const Qcord = require("../qcord.plugin.js");
const config = require("../src/config");
const {ACTIVE_SCHEME, MAX_DECODED_FILE_SIZE} = require("../src/constants");
let store={}, channel="100", draftText="", staged=[], toasts=[];
const channels = new Map([["100",{type:1,recipients:["2"]}],["200",{type:1,recipients:["3"]}],["300",{type:3,recipients:["2","3"]}]]);
const publicText = key => key.export({type:"spki",format:"base64"});
const privateText = key => key.export({type:"pkcs8",format:"base64"});
global.document = {querySelector:()=>null,querySelectorAll:()=>[]};
global.BdApi = {
    Data:{load:(n,k)=>structuredClone(store[k]),save:(n,k,v)=>{store[k]=structuredClone(v);}},
    Webpack:{getStore:name=>({ChannelStore:{getChannel:id=>channels.get(id)},SelectedChannelStore:{getChannelId:()=>channel},DraftStore:{getDraft:()=>draftText},UserStore:{getUser:id=>({username:"user"+id})}})[name],
        getByKeys: key=>key==="addFiles"?{addFiles:async data=>staged.push(data)}:null},
    UI:{showToast:(text)=>toasts.push(text)}
};
function client(Type=MessageCrypto) {
    store={};config.initialize();
    return Object.assign(new Type(),{running:true,enabled:true,session:{},conversationEpoch:{},keyPairs:new Map(),keyTasks:new Map(),schemeStatus:{},pendingSends:new Map(),renderedMessages:new Map(),fileDecodes:new WeakMap()});
}
async function pair(Type=MessageCrypto){const sender=client(Type),mine=await sender.generateKeys(ACTIVE_SCHEME),contact=await PQC.generateKeyPair(ACTIVE_SCHEME);sender.saveRecipients("100",[{user_id:"2",public_key_spki_base64:publicText(contact.publicKey)}],ACTIVE_SCHEME);return {sender,mine,contact};}
const flip=v=>{const b=Buffer.from(v,"base64");b[0]^=1;return b.toString("base64");};

test("ML-KEM-768 key sizes, exported dk restoration, fresh randomness, and implicit rejection",async()=>{
    const keys=await PQC.generateKeyPair(ACTIVE_SCHEME);
    assert.equal(keys.publicKey.bytes.length,1184);assert.equal(keys.privateKey.bytes.length,2400);
    const dk=PQC.createPrivateKey(privateText(keys.privateKey)),ek=PQC.createPublicKey(publicText(keys.publicKey));
    assert.ok(PQC.createPublicKey(dk).equals(ek));
    const a=await PQC.encapsulate(ek),b=await PQC.encapsulate(ek);
    assert.equal(a.ciphertext.length,1088);assert.equal(a.sharedKey.length,32);assert.notDeepEqual(a.ciphertext,b.ciphertext);
    assert.deepEqual(await PQC.decapsulate(dk,a.ciphertext),a.sharedKey);
    const bad=Buffer.from(a.ciphertext);bad[0]^=1;assert.notDeepEqual(await PQC.decapsulate(dk,bad),a.sharedKey);
    await assert.rejects(PQC.generateKeyPair("ml-kem-256"));
    const invalid=publicText(keys.publicKey);assert.throws(()=>PQC.createPublicKey(invalid.slice(0,-4)));
});

test("educational NTT multiplication matches independent ring multiplication",()=>{
    const a=Array.from({length:256},(_,i)=>(i*71+19)%3329),b=Array.from({length:256},(_,i)=>(i*11+2)%3329);
    assert.deepEqual(L.ntt(L.ntt(a),true),a);
    const expected=Array(256).fill(0);
    for(let i=0;i<256;i++)for(let j=0;j<256;j++)expected[(i+j)%256]=L.mod(expected[(i+j)%256]+(i+j>=256?-1:1)*a[i]*b[j]);
    assert.deepEqual(L.ntt(L.multiply(L.ntt(a),L.ntt(b)),true),expected);
    assert.deepEqual(L.bits([65]),[1,0,0,0,0,0,1,0]);
    for(let i=0;i<3329;i++)for(const d of [1,4,10])assert.equal(L.compress(i,d),Math.round(2**d*i/3329)%2**d);
    assert.equal(L.decompress(1,1),1665);
});

test("actual educational traces reproduce encapsulation and reconstruct key noise",async()=>{
    for(let i=0;i<5;i++){
        const keys=await PQC.generateKeyPair(ACTIVE_SCHEME),enc=await PQC.encapsulate(keys.publicKey,true);
        const recovered=L.decapsulationTrace(keys.privateKey.bytes,enc.ciphertext);
        assert.deepEqual(recovered.m,enc.trace.m);
        const priv=L.privateTrace(keys.publicKey.bytes,keys.privateKey.bytes);
        assert.ok([...priv.s,...priv.e].every(p=>p.length===256&&p.every(c=>Math.abs(c)<=2)));
        const damaged=Uint8Array.from(enc.ciphertext);damaged[50]^=1;
        assert.throws(()=>L.encapsulationTrace(keys.publicKey.bytes,enc.trace.m,damaged),/did not match/);
    }
});

test("one attachment opens with either participant's dk; preview corresponds to the attached bytes",async()=>{
    const {sender,contact}=await pair();const message="A private message 👋\nα + β = γ\n<script>alert(1)</script>";
    sender.enabled=false; // Manual learning composition works while automatic mode is off.
    const prepared=await sender.encryptMessage("100",message,{inspect:true});
    assert.equal(prepared.recovery.text,message);assert.equal(prepared.packet.qcord_version,3);
    assert.equal(prepared.packet.kem_algorithm,ACTIVE_SCHEME);assert.equal(prepared.packet.recipients.length,2);
    assert.ok(!prepared.wire.includes(message));assert.ok(!prepared.wire.includes(privateText(contact.privateKey)));
    assert.ok(!prepared.wire.includes(Buffer.from(prepared.trace.m).toString("base64")));
    assert.equal(await sender.decryptMessage(prepared.wire,"100"),message);
    const receiver=client();receiver.keyPairs.set(ACTIVE_SCHEME,contact);
    assert.equal(await receiver.decryptMessage(prepared.wire,"100"),message);
    const unrelated=await PQC.generateKeyPair(ACTIVE_SCHEME);receiver.keyPairs.set(ACTIVE_SCHEME,unrelated);
    await assert.rejects(receiver.decryptMessage(prepared.wire,"100"),/not addressed/);
    receiver.keyPairs.clear();await assert.rejects(receiver.decryptMessage(prepared.wire,"100"),/No saved/);
});

test("modified ciphertext, authenticated metadata, algorithms, and wrong channels are rejected",async()=>{
    const {sender}=await pair(),wire=await sender.encryptMessage("100","Secret");
    const mutations=[p=>p.channel_id="200",p=>p.qcord_version=2,p=>p.kem_algorithm="ml-kem-512",p=>p.encryption_algorithm="none",p=>p.key_derivation_algorithm="none",p=>p.recipient_key_fingerprints_sha256.reverse(),p=>p.recipients.push(p.recipients[0]),
        p=>p.recipients[0].kem_ciphertext_base64=flip(p.recipients[0].kem_ciphertext_base64),p=>p.recipients[0].wrapped_message_key.authentication_tag_base64=flip(p.recipients[0].wrapped_message_key.authentication_tag_base64),
        p=>p.encrypted_message.nonce_base64=flip(p.encrypted_message.nonce_base64),p=>p.encrypted_message.ciphertext_base64=flip(p.encrypted_message.ciphertext_base64),p=>p.encrypted_message.authentication_tag_base64=flip(p.encrypted_message.authentication_tag_base64)];
    for(const mutate of mutations){const packet=JSON.parse(wire);mutate(packet);await assert.rejects(sender.decryptMessage(JSON.stringify(packet),"100"));}
    await assert.rejects(sender.decryptMessage(wire,"200"),/wrong channel/);
    await assert.rejects(sender.encryptMessage("300","secret"),/one-to-one/);
    await assert.rejects(sender.encryptMessage("100","a".repeat(MAX_DECODED_FILE_SIZE)),/1 MiB/);
    await assert.rejects(sender.encryptMessage("100",""),/Write a message/);
});

test("manual staging binds the exact preview, channel and current contact key; blocks plaintext captions",async()=>{
    const {sender}=await pair(Qcord),prepared=await sender.encryptMessage("100","Learning",{inspect:true});staged=[];channel="200";
    await assert.rejects(sender.stageLearningDraft(prepared),/selected recipient/);channel="100";draftText="plain";
    await assert.rejects(sender.stageLearningDraft(prepared),/Clear the Discord composer/);draftText="";
    await sender.stageLearningDraft(prepared);assert.equal(staged.length,1);
    assert.equal(await staged[0].files[0].file.text(),prepared.wire);
    const replacement=await PQC.generateKeyPair(ACTIVE_SCHEME);sender.saveRecipients("100",[{user_id:"2",public_key_spki_base64:publicText(replacement.publicKey)}],ACTIVE_SCHEME);
    await assert.rejects(sender.stageLearningDraft(prepared),/key changed/);
});

test("automatic send never falls back to plaintext and cancels when the toggle changes",async()=>{
    const {sender}=await pair(Qcord);staged=[];toasts=[];
    const result=await sender.prepareMessageFile("100","Automatic");assert.equal(result.shouldClear,true);assert.equal(staged.length,1);
    const fail=await sender.prepareMessageFile("200","Keep this draft");assert.equal(fail.shouldClear,false);assert.equal(staged.length,1);
    const old=sender.encryptMessage.bind(sender);let resume;
    sender.encryptMessage=async(...args)=>{await new Promise(r=>resume=r);return old(...args);};
    const pending=sender.prepareMessageFile("100","Cancel me");
    const duplicate=await sender.prepareMessageFile("100","Cancel me");assert.equal(duplicate.shouldClear,false);
    sender.setEnabled(false);sender.setEnabled(true);resume();assert.equal((await pending).shouldClear,false);assert.equal(staged.length,1);
    assert.equal(store.learning_quantum_conversations,true);
});

test("existing configuration and decapsulation keys are not erased by the fresh edition",()=>{
    store={key_pairs:{"ml-kem-512":{private_key_pkcs8_base64:"old private key"}},encrypt_outgoing_messages:true};
    config.initialize();assert.equal(config.load("quantum_conversations"),undefined);assert.equal(store.key_pairs["ml-kem-512"].private_key_pkcs8_base64,"old private key");
    store.learning_config_version=99;assert.throws(()=>config.initialize(),/Unsupported/);
});

for (const scheme of ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]) {
    test(scheme + " trace, saved keys, two-party round trip and BOM preservation", async () => {
        const params = require("../src/parameters").parameters(scheme);
        const sender = client(), own = await sender.generateKeys(scheme), peer = await PQC.generateKeyPair(scheme);
        assert.equal(own.publicKey.bytes.length, params.publicBytes);
        assert.equal(own.privateKey.bytes.length, params.privateBytes);
        sender.saveRecipients("100", [{user_id:"2",public_key_spki_base64:publicText(peer.publicKey)}], scheme);
        const messages = ["\uFEFFHello", "\uFEFF\uFEFF", "middle\uFEFFend\uFEFF", "\u0000\r\n\uFFFD"];
        for (const message of messages) {
            const draft = await sender.encryptMessage("100", message, {inspect:true,scheme});
            assert.equal(draft.recovery.text, message);
            assert.equal(draft.trace.ciphertext.length,params.ciphertextBytes);
            assert.equal(await sender.decryptMessage("\uFEFF" + draft.wire, "100"), message);
            assert.notEqual(draft.wire.charCodeAt(0), 0xFEFF);
            const recovery = L.decapsulationTrace(peer.privateKey.bytes, draft.trace.ciphertext, scheme);
            assert.deepEqual(recovery.m, draft.trace.m);
            const receiver = Object.assign(new MessageCrypto(), {running:true,session:{},keyPairs:new Map([[scheme,peer]]),keyTasks:new Map()});
            assert.equal(await receiver.decryptMessage(draft.wire,"100"),message);
            const secret = L.privateTrace(own.publicKey.bytes,own.privateKey.bytes,scheme);
            assert.equal(secret.s.length,params.k);
            assert.ok([...secret.s,...secret.e].every(p=>p.every(x=>Math.abs(x)<=params.eta1)));
        }
        await assert.rejects(sender.encryptMessage("100","bad\uD800",{scheme}),/unpaired Unicode surrogate/);
        const wrong = scheme === "ml-kem-512" ? "ml-kem-768" : "ml-kem-512";
        assert.throws(()=>sender.saveRecipients("100",[{user_id:"2",public_key_spki_base64:publicText(peer.publicKey)}],wrong),/selected ML-KEM/);
    });
}

test("changing parameters preserves all identities and contact bindings, including concurrent key generation", async () => {
    const sender = client(Qcord), schemes = ["ml-kem-512","ml-kem-768","ml-kem-1024"];
    await Promise.all(schemes.map(s=>sender.generateKeys(s)));
    const before=structuredClone(store.learning_key_pairs);
    assert.equal(Object.keys(before).length,3);
    for (const scheme of schemes) {
        const peer=await PQC.generateKeyPair(scheme);
        sender.saveRecipients("100",[{user_id:"2",public_key_spki_base64:publicText(peer.publicKey)}],scheme);
    }
    assert.equal(sender.getSavedPartners().length,3);
    for (const scheme of schemes) {
        sender.setScheme(scheme);
        const wire=await sender.encryptMessage("100","keep my keys");
        assert.equal(JSON.parse(wire).kem_algorithm,scheme);
        const other=schemes.find(s=>s!==scheme);sender.setScheme(other);
        assert.equal(await sender.decryptMessage(wire,"100"),"keep my keys");
    }
    assert.deepEqual(store.learning_key_pairs,before);
    sender.removePartner("100","ml-kem-512");
    assert.equal(sender.getSavedPartners().length,2);
    assert.ok(sender.getRecipients("100","ml-kem-768").length);
});

test("plugin and source files are UTF-8 without an added BOM", () => {
    const fs=require("node:fs"),path=require("node:path");
    for(const file of ["qcord.plugin.js",...fs.readdirSync("src").map(f=>path.join("src",f))]) {
        const bytes=fs.readFileSync(file);
        assert.notEqual(bytes.subarray(0,3).toString("hex"),"efbbbf",file);
    }
});
