"use strict";

const SCHEMES = ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f"];

module.exports = {
    NAME: "Qcord",
    // One cache name for settings and keys: Windows filenames ignore case.
    KEY_STORE: "qcord",
    SCHEMES,
    KEM_SCHEMES: SCHEMES.filter(scheme => scheme.startsWith("ml-kem")),
    PREFIX: "qcord:v1:b64:",
    ENCRYPTED_PREFIX: "qcord:v2:pqc:",
    BASE64_RE: /^[A-Za-z0-9+/]*={0,2}$/,
    MESSAGE_SELECTOR: '[id^="message-content-"]',
    BUTTON_SELECTOR: ".qcord-button",
    DECODED_SELECTOR: ".qcord-plain",
    FILE_NAME_RE: /\.qcord$|^qcord_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt$/i,
    MAX_DECODED_FILE_SIZE: 1024 * 1024
};
