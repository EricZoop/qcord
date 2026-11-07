import React from "react";
import {createRoot} from "react-dom/client";
import {Buffer} from "buffer";
import Qcord from "../src/plugin.js";
import {PQC} from "../src/pqc.js";

globalThis.Buffer = Buffer;
const data = {};
const state = {channel: "100", staged: [], sent: [], notices: []};
const actions = {sendMessage: async (id, message) => { state.sent.push({id,message}); return {shouldClear:true}; }, editMessage() {}};
const channels = {"100":{type:1,recipients:["2"]},"200":{type:1,recipients:["3"]}};
globalThis.BdApi = {
    React, ReactDOM: {createRoot},
    Data: {load: (_,key) => data[key],save: (_,key,value) => {data[key]=value;}},
    DOM: {addStyle: (_,text) => {const el=document.createElement("style");el.textContent=text;document.head.append(el);},removeStyle(){}},
    Webpack: {
        getByKeys: key => key==="sendMessage"?actions:key==="addFiles"?{addFiles: async item=>{state.staged.push(item);}}:null,
        getStore: name => ({SelectedChannelStore:{getChannelId:()=>state.channel},ChannelStore:{getChannel:id=>channels[id]},UserStore:{getUser:id=>({username:id==="2"?"maya":"alex",globalName:id==="2"?"Maya":"Alex",avatar:"a_abcdef"})}})[name]
    },
    UI: {showToast:text=>state.notices.push(text),showConfirmationModal:(_,__,options)=>options.onConfirm?.()},
    Logger: {warn:()=>{}}
};
const plugin=new Qcord();plugin.start();
for (const scheme of ["ml-kem-512","ml-kem-768","ml-kem-1024"]) {
    const contact=await PQC.generateKeyPair(scheme);
    for(const [id,user] of [["100","2"],["200","3"]])plugin.saveRecipients(id,[{user_id:user,public_encaps:Buffer.from(contact.publicKey.bytes).toString("base64")}],scheme);
}
window.qcordTest={plugin,state,actions};
plugin.openComposer();
