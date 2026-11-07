import {serveFixture} from "./ui-server.mjs";

const port = Number(process.env.QCORD_UI_PORT || 4173);
if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("QCORD_UI_PORT must be a port number from 0 to 65535.");
const {server, url} = await serveFixture({port});
console.log(`Qcord local preview: ${url}\nDisposable keys and mocked Discord APIs. No Discord account is used.\nPress Ctrl+C to stop.`);
for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => server.close(() => process.exit(0)));
