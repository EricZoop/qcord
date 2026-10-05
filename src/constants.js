"use strict";

module.exports = {
    NAME: "Qcord",
    // One cache name for settings and keys: Windows filenames ignore case.
    KEY_STORE: "qcord",
    ACTIVE_SCHEME: "ml-kem-512",
    ENCRYPTED_PREFIX: "qcord:v1:pqc:",
    BASE64_RE: /^[A-Za-z0-9+/]*={0,2}$/,
    BUTTON_SELECTOR: ".qcord-button",
    DECODED_SELECTOR: ".qcord-plain",
    FILE_NAME_RE: /\.qcord$/i,
    MAX_DECODED_FILE_SIZE: 1024 * 1024
};
