"use strict";

const {MAX_DECODED_FILE_SIZE, NAME} = require("./constants");

// Own only Qcord's inserted nodes. Discord continues to own its attachment cards.
module.exports = class AttachmentDecoder {
    constructor(plugin) { this.plugin = plugin; this.entries = new Map(); }

    remove(card, entry) {
        entry.root?.unmount();
        entry.element?.remove();
        card.classList.remove("qcord-file-hidden");
        this.entries.delete(card);
    }

    clear() { for (const [card, entry] of this.entries) this.remove(card, entry); }
    retry() { for (const [card, entry] of this.entries) if (!entry.pending && !entry.element) this.remove(card, entry); }

    scan() {
        const plugin = this.plugin;
        if (!plugin.running || plugin.resetting) return;
        for (const [card, entry] of this.entries) {
            if (!card.isConnected || entry.session !== plugin.session || !entry.link.isConnected || entry.link.href !== entry.url || (entry.element && !entry.element.isConnected)) this.remove(card, entry);
        }
        for (const link of document.querySelectorAll('[id^="chat-messages-"] a[href]')) this.decode(link);
    }

    async decode(link) {
        const plugin = this.plugin;
        if (!plugin.running || plugin.resetting) return;
        let url, channelId, card;
        try {
            url = new URL(link.href);
            if (url.protocol !== "https:" || url.port || url.username || url.password || !["cdn.discordapp.com", "media.discordapp.net"].includes(url.hostname)) return;
            const path = url.pathname.match(/^\/attachments\/(\d+)\/\d+\/([^/]+)$/);
            if (!path || !/\.qcord$/i.test(decodeURIComponent(path[2]))) return;
            channelId = link.closest('[id^="chat-messages-"]')?.id?.match(/^chat-messages-(\d+)-\d+$/)?.[1];
            if (!channelId || path[1] !== channelId) return;
            plugin.getDirectPartner(channelId);
            card = link.closest('[class*="mosaicItem_"]') || link.closest('[class*="textContainer_"], [class*="fileWrapper_"], [class*="file_"], [class*="attachment_"]');
            if (!card || this.entries.has(card)) return;
        } catch { return; }

        const entry = {link, url: url.href, session: plugin.session, pending: true};
        this.entries.set(card, entry); // Deduplicate repeated observer scans during download.
        const current = () => plugin.running && !plugin.resetting && plugin.session === entry.session && this.entries.get(card) === entry && card.isConnected && link.isConnected && link.href === entry.url;
        try {
            const response = await BdApi.Net.fetch(entry.url, {timeout: 10000, redirect: "error", maxRedirects: 0});
            if (!response.ok || !current()) return;
            if (Number(response.headers.get("content-length")) > MAX_DECODED_FILE_SIZE) return;
            // BdApi.Net buffers the response; bound text parsing after download too.
            const wire = await response.text();
            if (Buffer.byteLength(wire) > MAX_DECODED_FILE_SIZE || !current()) return;
            const result = await plugin.openFile(wire, channelId);
            if (!current()) return;

            const element = document.createElement("div");
            element.className = "qcord-decrypted";
            element.setAttribute("aria-label", "Qcord decrypted message");
            const content = document.createElement("div");
            content.className = `qcord-message ${plugin.markupClass}`;
            element.append(content);
            const download = document.createElement("a");
            download.className = "qcord-download";
            download.href = entry.url;
            download.textContent = "Download .qcord";
            element.append(download);
            entry.element = element;
            card.after(element);
            entry.root = BdApi.ReactDOM.createRoot(content);
            entry.root.render(plugin.messageContent(result.text, channelId));
            card.classList.add("qcord-file-hidden");
        } catch (error) {
            entry.root?.unmount(); entry.element?.remove(); entry.root = null; entry.element = null;
            if (this.entries.get(card) === entry) card.classList.remove("qcord-file-hidden");
            if (current()) BdApi.Logger.warn(NAME, "Could not decrypt a Qcord attachment; the original file remains available.", error);
        } finally { entry.pending = false; }
    }
};
