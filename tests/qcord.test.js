"use strict";

const {test, afterEach} = require("node:test");
const assert = require("node:assert/strict");
const Qcord = require("../qcord.plugin.js");

function setup({enabled = true, missingActions = false} = {}) {
    const calls = [];
    const toasts = [];
    const saved = [];
    const styles = new Map();
    let undo;
    const actions = {
        sendMessage(...args) { calls.push({context: this, args}); return Promise.resolve({shouldClear: true}); },
        editMessage() {}
    };
    global.document = {querySelectorAll: () => []};
    global.BdApi = {
        Data: {load: () => enabled, save: (...args) => saved.push(args)},
        Webpack: {getByKeys: () => missingActions ? undefined : actions},
        UI: {showToast: (...args) => toasts.push(args)},
        DOM: {addStyle: (key, css) => styles.set(key, css), removeStyle: key => styles.delete(key)},
        Patcher: {
            instead(name, target, key, callback) {
                const original = target[key];
                target[key] = function(...args) { return callback(this, args, original); };
                undo = () => { target[key] = original; };
                return undo;
            },
            unpatchAll() { undo?.(); }
        }
    };
    const plugin = new Qcord();
    plugin.start();
    return {plugin, actions, calls, toasts, saved, styles};
}

afterEach(() => { delete global.BdApi; delete global.document; });

test("only symbols reach the send function; all UTF-8 characters round-trip", async () => {
    const {plugin, actions, calls} = setup();
    const plaintext = "Hello @everyone <@123> https://example.com\n世界 😀\t";
    const message = Object.freeze({content: plaintext, tts: false});
    const metadata = {messageReference: {message_id: "123"}};
    await actions.sendMessage("channel", message, undefined, metadata);
    const outgoing = calls[0].args[1];
    assert.notEqual(outgoing, message);
    assert.equal(message.content, plaintext);
    assert.equal(outgoing.tts, false);
    assert.equal(calls[0].args[3], metadata);
    assert.equal(calls[0].context, actions);
    const alphabet = Array.from("✀✁✂✃✄☎☏✆✉✍✎✏✐✑✒✓");
    const symbols = Array.from(outgoing.content);
    assert.ok(symbols.every(symbol => alphabet.includes(symbol)));
    const bytes = [];
    for (let i = 0; i < symbols.length; i += 2) {
        bytes.push(alphabet.indexOf(symbols[i]) * 16 + alphabet.indexOf(symbols[i + 1]));
    }
    assert.equal(new TextDecoder().decode(new Uint8Array(bytes)), plaintext);
    assert.equal(plugin.encodeText(""), "");
});

test("off forwards the original message and on persists the choice", async () => {
    const {plugin, actions, calls, saved} = setup({enabled: false});
    const message = {content: "hello"};
    await actions.sendMessage("channel", message);
    assert.equal(calls[0].args[1], message);
    plugin.setEnabled(true);
    await actions.sendMessage("channel", message);
    assert.notEqual(calls[1].args[1].content, "hello");
    assert.deepEqual(saved, [["Qcord", "enabled", true]]);
});

test("oversized, malformed and failed conversions never invoke the send function", async () => {
    const {plugin, actions, calls, toasts} = setup();
    await actions.sendMessage("channel", {content: "a".repeat(1000)});
    assert.equal(calls.length, 1); // Exactly 2,000 output symbols are allowed.
    const oversized = await actions.sendMessage("channel", {content: "a".repeat(1001)});
    assert.equal(oversized.shouldClear, false);
    await actions.sendMessage("channel", {content: 123});
    plugin.encodeText = () => { throw new Error("conversion failure"); };
    const failed = await actions.sendMessage("channel", {content: "private"});
    assert.equal(failed.shouldClear, false);
    assert.equal(calls.length, 1);
    assert.equal(toasts.length, 3);
});

test("attachment-only messages retain their options", async () => {
    const {actions, calls} = setup();
    const message = {content: "", attachments: [{id: "upload"}]};
    await actions.sendMessage("channel", message);
    assert.equal(calls[0].args[1].content, "");
    assert.equal(calls[0].args[1].attachments, message.attachments);
});

test("stop removes hooks and styles; missing send module leaves the effect unavailable", async () => {
    const {plugin, actions, calls, styles} = setup();
    assert.equal(styles.size, 1);
    plugin.stop();
    assert.equal(styles.size, 0);
    await actions.sendMessage("channel", {content: "plain"});
    assert.equal(calls[0].args[1].content, "plain");
    const missing = setup({missingActions: true});
    assert.equal(missing.plugin.running, false);
    assert.equal(missing.styles.size, 0);
    assert.equal(missing.toasts.length, 1);
});

test("composer switch mounts after attachments, toggles, remounts and cleans up", () => {
    const {plugin, saved} = setup({enabled: false});
    class Element {
        constructor() { this.attributes = {}; this.children = []; this.listeners = {}; }
        setAttribute(key, value) { this.attributes[key] = value; }
        getAttribute(key) { return this.attributes[key]; }
        append(...children) { this.children.push(...children); }
        addEventListener(type, callback) { this.listeners[type] = callback; }
        remove() { this.removed = true; }
    }
    let button;
    let insertions = 0;
    const anchor = {
        after(element) { button = element; this.nextElementSibling = element; insertions++; }
    };
    const attach = {closest: () => anchor};
    const composer = {querySelector: selector => selector === ".qcord-toggle" ? button : attach};
    const editor = {closest: () => composer};
    document.createElement = () => new Element();
    document.querySelectorAll = selector => selector === ".qcord-toggle" ? button ? [button] : [] : [editor];
    plugin.mountToggles();
    assert.equal(insertions, 1);
    assert.equal(button.type, "button");
    assert.equal(button.getAttribute("role"), "switch");
    assert.equal(button.getAttribute("aria-checked"), "false");
    plugin.mountToggles();
    assert.equal(insertions, 1);
    button.listeners.click({preventDefault() {}, stopPropagation() {}});
    assert.equal(button.getAttribute("aria-checked"), "true");
    assert.deepEqual(saved, [["Qcord", "enabled", true]]);
    button = undefined; // Discord replaced the composer after channel navigation.
    anchor.nextElementSibling = undefined;
    plugin.mountToggles();
    assert.equal(insertions, 2);
    assert.equal(button.getAttribute("aria-checked"), "true");
    plugin.stop();
    assert.equal(button.removed, true);
});
