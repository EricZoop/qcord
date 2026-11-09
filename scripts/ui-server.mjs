import {build} from "esbuild";
import {mkdir, writeFile} from "node:fs/promises";
import {createServer} from "node:http";
import {readFileSync} from "node:fs";

export async function serveFixture({port = 0} = {}) {
    await mkdir(".tools/ui", {recursive: true});
    await build({entryPoints: ["scripts/ui-fixture.js"], outfile: ".tools/ui/panel.js", bundle: true, platform: "browser", format: "esm", loader: {".css": "text", ".svg": "text", ".woff2": "dataurl"}});
    await writeFile(".tools/ui/index.html", '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Qcord test fixture</title><style>body{margin:0;background:#18191c;color:#b8bdc5;color-scheme:dark;font-family:system-ui}button,input,select{font-family:system-ui}.discord-markup-fixture{color:#111}.discord-markup-fixture code{color:#222}#qcord-test-chat{max-width:900px;margin:30px auto;padding:20px}#qcord-test-chat li{margin:16px 0;list-style:none}.header_fixture{margin:0;font-size:14px;color:#eee}.messageContent_fixture{min-height:22px}.accessories_fixture{margin-top:6px}.channelTextArea_fixture{display:flex;max-width:900px;margin:24px auto;padding:12px;background:#2b2d31}.channelTextArea_fixture [role=textbox]{flex:1;min-height:24px;outline:0}.buttons_fixture{display:flex}</style><script type="module" src="/panel.js"></script></html>');
    const server = createServer((request, response) => {
        const script = request.url === "/panel.js";
        response.setHeader("Content-Type", script ? "text/javascript" : "text/html");
        response.end(readFileSync(script ? ".tools/ui/panel.js" : ".tools/ui/index.html"));
    });
    await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", resolve); });
    return {server, url: `http://127.0.0.1:${server.address().port}`};
}
