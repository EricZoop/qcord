import React from "react";
import {createRoot} from "react-dom/client";
import {Buffer} from "buffer";
import Qcord from "../src/plugin.js";
import {PQC} from "../src/pqc.js";
import packet from "../src/packet.js";
import DSA from "../src/mldsa.js";
import message from "../src/message.js";
import {installFilePreview} from "./preview-files.js";

globalThis.Buffer = Buffer;
const data = {};
const state = {channel: "100", staged: [], sent: [], notices: [], downloads: [], markdownThrows: false, encapsulations: 0};
const downloads = new Map(), messageAuthors = new Map();
// A small stand-in for Discord's renderer: tests verify delegation and safe React text.
const markdown = {reactParserFor() {}, parse: text => {
    if (state.markdownThrows) throw new Error("Mock renderer failed");
    return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) => part.startsWith("**") ? React.createElement("strong", {key: i}, part.slice(2, -2)) : part.startsWith("`") ? React.createElement("code", {key: i}, part.slice(1, -1)) : part);
}};
const actions = {sendMessage: async (id, message) => { state.sent.push({id,message}); return {shouldClear:true}; }, editMessage() {}};
const patches=[];
const channels = {"100":{type:1,recipients:["2"]},"200":{type:1,recipients:["3"]}};
globalThis.BdApi = {
    React, ReactDOM: {createRoot},
    Data: {load: (_,key) => structuredClone(data[key]),save: (_,key,value) => {data[key]=structuredClone(value);},delete: (_,key) => {delete data[key];}},
    DOM: {addStyle: (_,text) => {const el=document.createElement("style");el.textContent=text;document.head.append(el);},removeStyle(){}},
    Webpack: {
        getByKeys: key => key==="parse"?markdown:key==="markup"?{markup:"discord-markup-fixture"}:key==="sendMessage"?actions:key==="addFiles"?{addFiles: async item=>{state.staged.push(item);}}:null,
        getStore: name => ({SelectedChannelStore:{getChannelId:()=>state.channel},ChannelStore:{getChannel:id=>channels[id]},MessageStore:{getMessage:(_,id)=>({author:{id:messageAuthors.get(id)}})},UserStore:{getCurrentUser:()=>({id:"1"}),getUser:id=>({username:id==="2"?"maya":"alex",globalName:id==="2"?"Maya":"Alex",avatar:"a_abcdef"})}})[name]
    },
    UI: {showToast:text=>state.notices.push(text),showConfirmationModal:(_,__,options)=>options.onConfirm?.()},
    Logger: {warn:()=>{}}
};
BdApi.Patcher={instead:(_,object,key,callback)=>{const original=object[key];object[key]=function(...args){return callback(this,args,original);};const undo=()=>{object[key]=original;};patches.push(undo);return undo;},unpatchAll:()=>{for(const undo of patches.splice(0).reverse())undo();}};
BdApi.Net = {fetch: async (url, options) => {
    state.downloads.push({url, options});
    const item=downloads.get(url);
    if (!item) return {ok:false};
    if (item.wait) await item.wait;
    return {ok:true, headers:{get:()=>String(item.size ?? new TextEncoder().encode(item.wire).length)}, text:async()=>item.wire};
}};
const plugin=new Qcord();plugin.start();
const prepare=plugin.prepareEncapsulation.bind(plugin);
plugin.prepareEncapsulation=(...args)=>{state.encapsulations++;return prepare(...args);};
const chat=document.createElement("div");chat.id="qcord-test-chat";document.body.append(chat);
const composer=document.createElement("div");composer.className="channelTextArea_fixture";
const editor=document.createElement("div");editor.contentEditable="true";editor.setAttribute("role","textbox");editor.setAttribute("aria-label","Discord draft");
const controls=document.createElement("div");controls.className="buttons_fixture";composer.append(editor,controls);document.body.append(composer);plugin.mountButtons();
editor.addEventListener("keydown",async event=>{if(event.key==="Enter"&&!event.shiftKey){event.preventDefault();const result=await actions.sendMessage(state.channel,{content:editor.innerText});if(result.shouldClear)editor.replaceChildren();}});
const observer=new MutationObserver(records=>{for(const record of records)plugin.observer(record);});observer.observe(document.body,{childList:true,subtree:true,attributes:true,attributeFilter:["class","title","aria-label","href"]});
function addAttachment(wire, {id="1",channel="100",url,delay=false,size,authorId}={}) {
    url ||= `https://cdn.discordapp.com/attachments/${channel}/${id}/message.qcord?ex=fixture`;
    if (!authorId) {
        try { const file=JSON.parse(wire), own=data.key_sets["ml-kem-768"].public_signature;
            authorId = !DSA.blank(file.signature_sigma) && PQC.verify(DSA.encodeSignature(file.signature_sigma,"ml-kem-768"),packet.signaturePayload(file),own,"ml-kem-768") ? "1" : "2";
        } catch { authorId="2"; }
    }
    messageAuthors.set(id,authorId);
    const item={wire,size};
    if(delay)item.wait=new Promise(resolve=>{item.release=resolve;});
    downloads.set(url,item);
    const message=document.createElement("li");message.id=`chat-messages-${channel}-${id}`;
    const contents=document.createElement("div");contents.className="contents_fixture";
    const heading=document.createElement("h3");heading.className="header_fixture";heading.textContent="Maya  4:44 PM";
    const slot=document.createElement("div");slot.id=`message-content-${id}`;slot.className="messageContent_fixture";contents.append(heading,slot);message.append(contents);
    const accessories=document.createElement("div");accessories.className="accessories_fixture";message.append(accessories);
    const card=document.createElement("div");card.className="mosaicItem_fixture";
    const link=document.createElement("a");link.href=url;link.textContent="message.qcord";
    card.append(link);accessories.append(card);chat.append(message);
    return url;
}
const contact=await PQC.generateKeyPair("ml-kem-768");
const contactSignature = await PQC.generateSignatureKeys("ml-kem-768");
for(const [id,user] of [["100","2"],["200","3"]])plugin.saveRecipients(id,[{user_id:user,public_encaps:Buffer.from(contact.publicKey.bytes).toString("base64"),public_signature:Buffer.from(contactSignature.publicKey).toString("base64")}]);
window.qcordTest={plugin,state,actions,data,addAttachment,releaseDownload:url=>downloads.get(url)?.release?.(),incomingWire:async text=>{
    const keys=await plugin.generateKeys();
    const result=await PQC.encapsulate(keys.publicKey);
    try {const file=packet.fromCiphertext(result.ciphertext);file.encrypted_message=message.seal(text,result.sharedKey,file);file.signature_sigma=DSA.decodeSignature(PQC.sign(packet.signaturePayload(file),Buffer.from(contactSignature.privateKey).toString("base64"),"ml-kem-768"),"ml-kem-768");return packet.stringify(file);}
    finally {result.sharedKey.fill(0);result.m.fill(0);}
},useRecipientIdentity:()=>{
    plugin.attachments.clear();
    data.key_sets["ml-kem-768"].public_encaps=Buffer.from(contact.publicKey.bytes).toString("base64");
    data.key_sets["ml-kem-768"].private_decaps=Buffer.from(contact.privateKey.bytes).toString("base64");
    data.recipients=[];plugin.keyPairs.clear();plugin.keyTasks.clear();plugin.session={};
}};
installFilePreview(plugin, data);
plugin.openComposer();

// Signature demos are local preview controls, outside the product UI.
const signatureDemos = document.createElement("nav");
signatureDemos.className = "qcord-signature-demos";
signatureDemos.setAttribute("aria-label", "Signature demos");
let demoIndex = 50000;
async function signatureDemo(failed = false) {
    plugin.composerDialog?.close();
    plugin.saveRecipients("100", [{user_id: "2", public_encaps: Buffer.from(contact.publicKey.bytes).toString("base64"), public_signature: Buffer.from(contactSignature.publicKey).toString("base64")}]);
    plugin.setAutomatic("decrypt", true); plugin.setAutomatic("verify", true);
    const file = JSON.parse(await window.qcordTest.incomingWire(failed ? "This signature was changed. Click the shield to inspect the mismatch." : "Signed by Maya. Click the check to walk through verification."));
    if (failed) { const c = Buffer.from(file.signature_sigma.c_tilde, "base64"); c[0] ^= 1; file.signature_sigma.c_tilde = c.toString("base64"); }
    const id = String(demoIndex++), wire = packet.stringify(file);
    addAttachment(wire, {id});
    return id;
}
window.qcordTest.signatureDemo = signatureDemo;
for (const [label, failed] of [["Verified message", false], ["Failed signature", true]]) {
    const button = document.createElement("button"); button.textContent = label;
    button.addEventListener("click", () => signatureDemo(failed)); signatureDemos.append(button);
}
document.body.append(signatureDemos);
