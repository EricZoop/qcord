import {existsSync} from "node:fs";
import {join} from "node:path";
import {chromium} from "playwright";

export async function launchBrowser() {
    if (process.env.QCORD_BROWSER) {
        if (!existsSync(process.env.QCORD_BROWSER)) throw new Error(`QCORD_BROWSER does not exist: ${process.env.QCORD_BROWSER}`);
        console.log(`Browser: ${process.env.QCORD_BROWSER}`);
        return chromium.launch({headless: true, executablePath: process.env.QCORD_BROWSER});
    }
    const candidates = process.platform === "win32" ? [
        ...[process.env["ProgramFiles(x86)"], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean).map(root => join(root, "Microsoft", "Edge", "Application", "msedge.exe")),
        ...[process.env.ProgramFiles, process.env["ProgramFiles(x86)"], process.env.LOCALAPPDATA].filter(Boolean).map(root => join(root, "Google", "Chrome", "Application", "chrome.exe"))
    ] : process.platform === "darwin" ? ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"] : ["/usr/bin/microsoft-edge", "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];
    const executablePath = [...candidates, chromium.executablePath()].find(existsSync);
    if (!executablePath) throw new Error("No installed Edge, Chrome or Playwright Chromium was found. Set QCORD_BROWSER to a browser executable, or run npx playwright install chromium using your trusted CA configuration.");
    console.log(`Browser: ${executablePath}`);
    return chromium.launch({headless: true, executablePath});
}
