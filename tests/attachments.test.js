"use strict";

// Run with: node --test tests/attachments.test.js
const assert = require("node:assert/strict");
const {test} = require("node:test");
const Qcord = require("../qcord.plugin.js");

// Only the DOM operations used by attachment rendering; no runtime dependencies.
class Element {
    constructor(className = "", parent = null) {
        this.className = className;
        this.parentElement = parent;
        this.isConnected = true;
        this.textContent = "";
        this.classList = {
            add: name => { if (!this.className.split(" ").includes(name)) this.className += ` ${name}`; },
            remove: name => { this.className = this.className.split(" ").filter(c => c !== name).join(" "); },
            contains: name => this.className.split(" ").includes(name)
        };
    }
    closest(selector) {
        for (let node = this; node; node = node.parentElement) {
            if ([...selector.matchAll(/\[class\*="([^"]+)"\]/g)].some(m => node.className.includes(m[1]))) return node;
        }
        return null;
    }
    after(element) { this.nextSibling = element; element.parentElement = this.parentElement; }
    remove() { this.isConnected = false; }
}

test("long-message staging and attachment decoding", async () => {
    const elements = [];
    const links = [];
    const toasts = [];
    const sent = [];
    const downloads = [];
    let staged;
    let sendHook;
    let fetchResponse;
    let stagingFails = false;
    const actions = {sendMessage() {}, editMessage() {}};
    global.document = {
        createElement: () => { const node = new Element(); elements.push(node); return node; },
        querySelectorAll: selector => {
            if (selector === '[id^="chat-messages-"] a[href]') return links;
            if (selector.startsWith(".")) return elements.filter(e => e.isConnected && e.classList.contains(selector.slice(1)));
            return [];
        }
    };
    global.BdApi = {
        Data: {load: () => true, save() {}},
        DOM: {addStyle() {}, removeStyle() {}},
        UI: {showToast: (...args) => toasts.push(args)},
        Logger: {warn() {}},
        Webpack: {getByKeys: key => key === "sendMessage" ? actions : {
            addFiles: async options => {
                if (stagingFails) throw new Error("Upload unavailable");
                staged = options;
            }
        }},
        Patcher: {instead: (_name, _actions, _method, callback) => { sendHook = callback; return () => {}; }, unpatchAll() {}},
        Net: {fetch: async (url, options) => { downloads.push({url, options}); return fetchResponse(); }}
    };
    const plugin = new Qcord();
    plugin.start();
    const original = (...args) => { sent.push(args); return Promise.resolve({shouldClear: true}); };
    const source = "A long message with Unicode \u{1f512}\n<script>alert('text only')</script> ".repeat(80);
    const draft = {content: source};
    assert.deepEqual(await sendHook(null, ["123", draft], original), {shouldClear: true, shouldRefocus: true});
    assert.equal(sent.length, 0);
    assert.equal(draft.content, source);
    assert.equal(staged.channelId, "123");
    const file = staged.files[0].file;
    assert.match(file.name, /^qcord_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt$/);
    const encoded = await file.text();
    assert.ok(encoded.length > 2000);
    assert.equal(plugin.decodeText(encoded), source);
    // The old grouped Base64 regex could overflow the stack on large text files.
    const large = "x".repeat(500000);
    assert.equal(plugin.decodeText(plugin.encodeText(large)), large);
    for (const payload of ["====", "A===", "AA=A", "AB==", "YQ", "YQ==\n", "/w=="]) {
        assert.equal(plugin.decodeText(`qcord:v1:b64:${payload}`), null);
    }
    stagingFails = true;
    assert.equal((await sendHook(null, ["123", draft], original)).shouldClear, false);
    assert.equal(sent.length, 0);
    assert.equal((await sendHook(null, ["123", {content: "x".repeat(1491)}], original)).shouldClear, false);
    await sendHook(null, ["123", {content: "x".repeat(1488)}], original);
    assert.equal(sent.at(-1)[1].content.length, 1997);
    await sendHook(null, ["123", {content: ""}], original);
    assert.equal(sent.at(-1)[1].content, ""); // Attachment-only send remains possible.

    const url = `https://cdn.discordapp.com/attachments/123/456/${file.name}?ex=abc&is=def&hm=signed`;
    function fixture(className, mosaic = false, href = url) {
        const outer = mosaic ? new Element("mosaicItem_abc") : null;
        const inner = new Element(className, outer);
        const link = new Element("", inner);
        link.href = href;
        elements.push(inner, ...(outer ? [outer] : []));
        return {card: outer || inner, link};
    }
    fetchResponse = () => new Response(encoded);
    for (const className of ["file_abc", "textContainer_abc", "fileWrapper_abc", "attachment_abc"]) {
        for (const mosaic of [false, true]) {
            const {card, link} = fixture(className, mosaic);
            const before = downloads.length;
            await Promise.all([plugin.decodeFile(link), plugin.decodeFile(link)]);
            assert.equal(downloads.length, before + 1);
            assert.equal(downloads.at(-1).url, url); // Keep the CDN signature.
            assert.equal(card.nextSibling.textContent, source);
            assert.ok(card.classList.contains("qcord-file-hidden"));
            const rendered = card.nextSibling;
            await plugin.decodeFile(link);
            assert.equal(card.nextSibling, rendered);
            assert.equal(downloads.length, before + 1);
        }
    }
    const visible = fixture("textContainer_abc", true);
    links.push(visible.link);
    plugin.scanMessages();
    await new Promise(setImmediate);
    assert.equal(visible.card.nextSibling.textContent, source);
    const beforeToggle = downloads.length;
    plugin.setDecoding(false);
    assert.equal(visible.card.nextSibling.isConnected, false);
    assert.equal(visible.card.classList.contains("qcord-file-hidden"), false);
    plugin.setDecoding(true);
    assert.equal(visible.card.nextSibling.textContent, source);
    assert.equal(visible.card.nextSibling.isConnected, true);
    assert.equal(downloads.length, beforeToggle);

    // Non-attachment links in a card must not clear a successful decode.
    const unrelated = new Element("", visible.card);
    unrelated.href = "https://discord.com/channels/123/456";
    await plugin.decodeFile(unrelated);
    assert.ok(visible.card.classList.contains("qcord-file-hidden"));
    for (const href of [url.replace("cdn.discordapp.com", "example.com"), url.replace("https:", "http:"), url.replace(file.name, "notes.txt")]) {
        const {card, link} = fixture("file_abc", false, href);
        const before = downloads.length;
        await plugin.decodeFile(link);
        assert.equal(downloads.length, before);
        assert.equal(card.nextSibling, undefined);
    }
    for (const response of [
        () => new Response("ordinary text"),
        () => new Response("denied", {status: 403}),
        () => new Response(encoded, {headers: {"content-length": "1048577"}}),
        () => new Response("x".repeat(1048577)),
        () => { throw new Error("Network unavailable"); }
    ]) {
        fetchResponse = response;
        const {card, link} = fixture("textContainer_abc");
        await plugin.decodeFile(link);
        assert.equal(card.classList.contains("qcord-file-hidden"), false);
        assert.equal(card.nextSibling, undefined);
    }
    let finishDownload;
    fetchResponse = () => new Promise(resolve => { finishDownload = resolve; });
    const pending = fixture("file_abc");
    const decoding = plugin.decodeFile(pending.link);
    plugin.stop();
    finishDownload(new Response(encoded));
    await decoding;
    assert.equal(pending.card.nextSibling, undefined);
    assert.equal(visible.card.classList.contains("qcord-file-hidden"), false);
});
