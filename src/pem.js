"use strict";

// Minimal, strict DER framing for the supported SPKI / PKCS#8 key shapes.
// Algorithm validation and private-key CHOICE handling live in pqc.js.
function pack(tag, ...values) {
    const body = Buffer.concat(values);
    const length = [];
    for (let n = body.length; n; n = Math.floor(n / 256)) length.unshift(n & 255);
    return Buffer.concat([Buffer.from([tag, ...(body.length < 128 ? [body.length] : [0x80 | length.length, ...length])]), body]);
}

function unpack(bytes) {
    const fields = [];
    for (let offset = 0; offset < bytes.length;) {
        if (offset + 2 > bytes.length) throw new Error("Truncated DER field.");
        const tag = bytes[offset++];
        let length = bytes[offset++];
        if (length & 0x80) {
            const count = length & 0x7f;
            if (!count || count > 3 || offset + count > bytes.length || bytes[offset] === 0) throw new Error("Invalid DER length.");
            length = 0;
            for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
            if (length < 128) throw new Error("Noncanonical DER length.");
        }
        if (offset + length > bytes.length) throw new Error("Truncated DER content.");
        fields.push({tag, value: bytes.subarray(offset, offset + length)});
        offset += length;
    }
    return fields;
}

function readPem(text, type) {
    if (typeof text !== "string" || text.length > 65536) throw new Error("Invalid PEM key.");
    const match = text.trim().match(/^-----BEGIN (PUBLIC|PRIVATE) KEY-----\s+([A-Za-z0-9+/=\s]+)-----END \1 KEY-----$/);
    if (!match || match[1] !== type) throw new Error("Invalid PEM key type.");
    const encoded = match[2].replace(/\s/g, "");
    const bytes = Buffer.from(encoded, "base64");
    if (!bytes.length || bytes.toString("base64") !== encoded) throw new Error("Invalid PEM Base64.");
    return bytes;
}

function writePem(bytes, type) {
    return `-----BEGIN ${type} KEY-----\n${bytes.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END ${type} KEY-----\n`;
}

module.exports = {pack, unpack, readPem, writePem};
