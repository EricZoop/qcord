// Local preview tools only; this module is never bundled into the Discord plugin.
import styles from "./preview-files.css";

export function installFilePreview(plugin, data) {
    const style = document.createElement("style");
    style.textContent = styles;
    document.head.append(style);
    const dock = document.createElement("nav");
    dock.className = "qcord-preview-files";
    dock.setAttribute("aria-label", "Preview files");
    const configButton = document.createElement("button");
    configButton.textContent = "qcord.config.json";
    const messageButton = document.createElement("button");
    messageButton.textContent = "message.qcord";
    messageButton.disabled = true;
    messageButton.title = "Prepare a message to inspect its file";
    dock.append(configButton, messageButton);
    document.body.append(dock);
    let latest = null;
    const serialize = plugin.serializeDraft.bind(plugin);
    plugin.serializeDraft = draft => {
        const result = serialize(draft);
        latest = {name: `${result.message_epoch}.qcord`, wire: result.wire};
        messageButton.textContent = latest.name;
        messageButton.disabled = false;
        messageButton.title = "Inspect the current message file";
        return result;
    };

    function showFile(name, read) {
        const dialog = document.createElement("dialog");
        dialog.className = "qcord-file-viewer";
        dialog.setAttribute("aria-label", "Preview file");
        const header = document.createElement("header");
        const title = document.createElement("strong");
        title.textContent = name;
        const refresh = document.createElement("button");
        refresh.textContent = "Refresh";
        const close = document.createElement("button");
        close.textContent = "Close file";
        header.append(title, refresh, close);
        const note = document.createElement("p");
        note.textContent = "Local preview · disposable keys · JSON";
        const pre = document.createElement("pre");
        pre.tabIndex = 0;
        pre.setAttribute("aria-label", "File contents");
        const code = document.createElement("code");
        code.className = "language-json";
        pre.append(code);
        function render() {
            const file = read();
            title.textContent = file.name;
            // Tokenize JSON into text nodes; never interpret file values as HTML.
            const tokens = /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]/g;
            const fragment = document.createDocumentFragment();
            let offset = 0;
            for (const match of file.wire.matchAll(tokens)) {
                fragment.append(document.createTextNode(file.wire.slice(offset, match.index)));
                const span = document.createElement("span");
                const token = match[0];
                const isKey = token.startsWith('"') && /^\s*:/.test(file.wire.slice(match.index + token.length));
                span.className = `json-${isKey ? "key" : token.startsWith('"') ? "string" : /^(?:true|false|null)$/.test(token) ? "literal" : /^[-\d]/.test(token) ? "number" : "punctuation"}`;
                span.textContent = token;
                fragment.append(span);
                offset = match.index + token.length;
            }
            fragment.append(document.createTextNode(file.wire.slice(offset)));
            code.replaceChildren(fragment);
        }
        render();
        refresh.addEventListener("click", render);
        close.addEventListener("click", () => dialog.close());
        dialog.addEventListener("close", () => dialog.remove(), {once: true});
        dialog.append(header, note, pre);
        document.body.append(dialog);
        dialog.showModal();
    }
    configButton.addEventListener("click", () => showFile("qcord.config.json", () => ({name: "qcord.config.json", wire: JSON.stringify(data, null, 2) + "\n"})));
    messageButton.addEventListener("click", () => { if (latest) showFile(latest.name, () => latest); });

    // A modal makes siblings inert, so keep the dock inside the active composer.
    // React mounts asynchronously and owns the composer's contents. Reattach
    // after a mount or close without placing preview tools in production UI.
    const observer = new MutationObserver(() => {
        const parent = plugin.composerDialog?.open ? plugin.composerDialog : document.body;
        if (dock.parentElement !== parent) parent.append(dock);
    });
    observer.observe(document.body, {childList: true, subtree: true});
    plugin.resets.add(() => {
        latest = null;
        messageButton.textContent = "message.qcord";
        messageButton.disabled = true;
    });
}
