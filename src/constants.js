"use strict";

// Older KEMs are retained only to read previously encrypted messages.
const SCHEMES = ["ml-kem-512", "ml-kem-768", "ml-kem-1024"];

module.exports = {
    NAME: "Qcord",
    // One cache name for settings and keys: Windows filenames ignore case.
    KEY_STORE: "qcord",
    SCHEMES,
    ACTIVE_SCHEME: "ml-kem-512",
    KEM_SCHEMES: SCHEMES.filter(scheme => scheme.startsWith("ml-kem")),
    ENCRYPTED_PREFIX: "qcord:v2:pqc:",
    BASE64_RE: /^[A-Za-z0-9+/]*={0,2}$/,
    BUTTON_SELECTOR: ".qcord-button",
    DECODED_SELECTOR: ".qcord-plain",
    FILE_NAME_RE: /\.qcord$/i,
    MAX_DECODED_FILE_SIZE: 1024 * 1024
};
