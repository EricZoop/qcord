"use strict";

// Separate storage preserves old identities without loading obsolete protocols.
const {KEY_STORE} = require("./constants");
const field = name => "learning_" + name;
const load = name => BdApi.Data.load(KEY_STORE, field(name));
const save = (name, value) => BdApi.Data.save(KEY_STORE, field(name), value);
function initialize() {
    const version = load("config_version");
    if (version != null && version !== 1) throw new Error("Unsupported Qcord learning configuration.");
    if (version == null) save("config_version", 1);
}
module.exports = {load, save, initialize};
