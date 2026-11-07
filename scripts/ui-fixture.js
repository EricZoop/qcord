import React from "react";
import {createRoot} from "react-dom/client";
import {Buffer} from "buffer";
import Qcord from "../src/plugin.js";
import {PQC} from "../src/pqc.js";
import packet from "../src/packet.js";
import message from "../src/message.js";

globalThis.Buffer = Buffer;
const data = {};
const state = {channel: "100", staged: [], sent: [], notices: [], downloads: [], markdownThrows: false};
const downloads = new Map();
// A small stand-in for Discord's renderer: tests verify delegation and safe React text.
const markdown = {reactParserFor() {}, parse: text => {
    if (state.markdownThrows) throw new Error("Mock renderer failed");
    return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, i) => part.startsWith("**") ? React.createElement("strong", {key: i}, part.slice(2, -2)) : part.startsWith("`") ? React.createElement("code", {key: i}, part.slice(1, -1)) : part);
}};
const actions = {sendMessage: async (id, message) => { state.sent.push({id,message}); return {shouldClear:true}; }, editMessage() {}};
const channels = {"100":{type:1,recipients:["2"]},"200":{type:1,recipients:["3"]}};
globalThis.BdApi = {
    React, ReactDOM: {createRoot},
    Data: {load: (_,key) => structuredClone(data[key]),save: (_,key,value) => {data[key]=structuredClone(value);},delete: (_,key) => {delete data[key];}},
    DOM: {addStyle: (_,text) => {const el=document.createElement("style");el.textContent=text;document.head.append(el);},removeStyle(){}},
    Webpack: {
        getByKeys: key => key==="parse"?markdown:key==="markup"?{markup:"discord-markup-fixture"}:key==="sendMessage"?actions:key==="addFiles"?{addFiles: async item=>{state.staged.push(item);}}:null,
        getStore: name => ({SelectedChannelStore:{getChannelId:()=>state.channel},ChannelStore:{getChannel:id=>channels[id]},UserStore:{getUser:id=>({username:id==="2"?"maya":"alex",globalName:id==="2"?"Maya":"Alex",avatar:"a_abcdef"})}})[name]
    },
    UI: {showToast:text=>state.notices.push(text),showConfirmationModal:(_,__,options)=>options.onConfirm?.()},
    Logger: {warn:()=>{}}
};
BdApi.Net = {fetch: async (url, options) => {
    state.downloads.push({url, options});
    const item=downloads.get(url);
    if (!item) return {ok:false};
    if (item.wait) await item.wait;
    return {ok:true, headers:{get:()=>String(item.size ?? new TextEncoder().encode(item.wire).length)}, text:async()=>item.wire};
}};
const plugin=new Qcord();plugin.start();
const chat=document.createElement("div");chat.id="qcord-test-chat";document.body.append(chat);
const observer=new MutationObserver(()=>plugin.observer());observer.observe(chat,{childList:true,subtree:true,attributes:true,attributeFilter:["href"]});
function addAttachment(wire, {id="1",channel="100",url,delay=false,size}={}) {
    url ||= `https://cdn.discordapp.com/attachments/${channel}/${id}/message.qcord?ex=fixture`;
    const item={wire,size};
    if(delay)item.wait=new Promise(resolve=>{item.release=resolve;});
    downloads.set(url,item);
    const message=document.createElement("li");message.id=`chat-messages-${channel}-${id}`;
    const card=document.createElement("div");card.className="mosaicItem_fixture";
    const link=document.createElement("a");link.href=url;link.textContent="message.qcord";
    card.append(link);message.append(card);chat.append(message);
    return url;
}
const contact=await PQC.generateKeyPair("ml-kem-768");
for(const [id,user] of [["100","2"],["200","3"]])plugin.saveRecipients(id,[{user_id:user,public_encaps:Buffer.from(contact.publicKey.bytes).toString("base64")}]);
window.qcordTest={plugin,state,actions,data,addAttachment,releaseDownload:url=>downloads.get(url)?.release?.(),incomingWire:async text=>{
    const keys=await plugin.generateKeys();
    const result=await PQC.encapsulate(keys.publicKey);
    try {const file=packet.fromCiphertext(result.ciphertext);file.encrypted_message=message.seal(text,result.sharedKey,file);return packet.stringify(file);}
    finally {result.sharedKey.fill(0);result.m.fill(0);}
},useRecipientIdentity:()=>{
    plugin.attachments.clear();
    data.public_encaps=Buffer.from(contact.publicKey.bytes).toString("base64");
    data.private_decaps=Buffer.from(contact.privateKey.bytes).toString("base64");
    data.recipients=[];plugin.keyPairs.clear();plugin.keyTasks.clear();plugin.session={};
}};
plugin.openComposer();
