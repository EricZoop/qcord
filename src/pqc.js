"use strict";

const {ml_kem512, ml_kem768, ml_kem1024} = require("@noble/post-quantum/ml-kem.js");
const {ml_dsa44, ml_dsa65, ml_dsa87} = require("@noble/post-quantum/ml-dsa.js");
const {slh_dsa_sha2_128f} = require("@noble/post-quantum/slh-dsa.js");
const {equalBytes} = require("@noble/post-quantum/utils.js");
const {pack, unpack, readPem, writePem} = require("./pem");

let Crypto;
try { Crypto = require("crypto"); }
catch { Crypto = null; }

// NIST algorithm identifiers used by SPKI / PKCS#8, including existing Node keys.
const algorithms = {
    "ml-kem-512": {impl: ml_kem512, oid: "608648016503040401"},
    "ml-kem-768": {impl: ml_kem768, oid: "608648016503040402"},
    "ml-kem-1024": {impl: ml_kem1024, oid: "608648016503040403"},
    "ml-dsa-44": {impl: ml_dsa44, oid: "608648016503040311"},
    "ml-dsa-65": {impl: ml_dsa65, oid: "608648016503040312"},
    "ml-dsa-87": {impl: ml_dsa87, oid: "608648016503040313"},
    "slh-dsa-sha2-128f": {impl: slh_dsa_sha2_128f, oid: "608648016503040315"}
};

function algorithm(scheme) {
    if (!Object.hasOwn(algorithms, scheme)) throw new Error("Unsupported PQC algorithm.");
    return algorithms[scheme];
}

function randomBytes(size) {
    if (!Crypto?.randomBytes) throw new Error("Discord must expose crypto.randomBytes for secure randomness.");
    return Uint8Array.from(Crypto.randomBytes(size));
}

// ponytail: bounded PQC operations run in the renderer; use a worker if larger
// signature suites cause UI stalls. Yield first so status updates can render.
async function run(operation) {
    await new Promise(resolve => setTimeout(resolve, 0));
    return operation();
}

class Key {
    constructor(scheme, type, bytes) {
        const expected = algorithm(scheme).impl.lengths[type === "public" ? "publicKey" : "secretKey"];
        if (bytes.length !== expected) throw new Error("Invalid PQC key length.");
        this.asymmetricKeyType = scheme;
        this.type = type;
        // Normalize bytes from Electron/Node contexts before passing them to noble.
        this.bytes = Uint8Array.from(bytes);
    }

    equals(other) {
        return other instanceof Key && this.type === other.type && this.asymmetricKeyType === other.asymmetricKeyType && equalBytes(this.bytes, other.bytes);
    }

    export({type, format}) {
        const privateKey = this.type === "private";
        if (type !== (privateKey ? "pkcs8" : "spki") || !["der", "pem"].includes(format)) throw new Error("Unsupported key export format.");
        const identifier = pack(0x30, pack(0x06, Buffer.from(algorithm(this.asymmetricKeyType).oid, "hex")));
        // RFC 9935 / RFC 9881 expanded-key CHOICE. SLH-DSA stores raw key bytes.
        const body = this.asymmetricKeyType.startsWith("slh-") ? this.bytes : pack(0x04, this.bytes);
        const der = privateKey
            ? pack(0x30, pack(0x02, Buffer.from([0])), identifier, pack(0x04, body))
            : pack(0x30, identifier, pack(0x03, Buffer.from([0]), this.bytes));
        return format === "der" ? der : writePem(der, privateKey ? "PRIVATE" : "PUBLIC");
    }
}

function importKey(pem, type) {
    const top = unpack(readPem(pem, type === "private" ? "PRIVATE" : "PUBLIC"));
    if (top.length !== 1 || top[0].tag !== 0x30) throw new Error("Invalid key sequence.");
    const fields = unpack(top[0].value);
    if (fields.length !== (type === "private" ? 3 : 2)) throw new Error("Unsupported key structure.");
    if (type === "private") {
        const version = fields.shift();
        if (version.tag !== 0x02 || version.value.toString("hex") !== "00") throw new Error("Unsupported private-key version.");
    }
    const [identifier, data] = fields;
    if (identifier.tag !== 0x30) throw new Error("Invalid key algorithm.");
    const oid = unpack(identifier.value);
    if (oid.length !== 1 || oid[0].tag !== 0x06) throw new Error("Invalid key algorithm.");
    const scheme = Object.keys(algorithms).find(name => algorithms[name].oid === oid[0].value.toString("hex"));
    const {impl} = algorithm(scheme);
    if (type === "public") {
        if (data.tag !== 0x03 || data.value[0] !== 0) throw new Error("Invalid public-key bit string.");
        return new Key(scheme, type, data.value.subarray(1));
    }
    if (data.tag !== 0x04) throw new Error("Invalid private-key octet string.");
    if (scheme.startsWith("slh-")) return new Key(scheme, type, data.value);
    const choice = unpack(data.value);
    if (choice.length !== 1) throw new Error("Invalid private-key encoding.");
    const {tag, value} = choice[0];
    if (tag === 0x04) return new Key(scheme, type, value);
    if (tag === 0x80) return new Key(scheme, type, impl.keygen(Uint8Array.from(value)).secretKey);
    if (tag === 0x30) {
        const parts = unpack(value);
        if (parts.length !== 2 || parts.some(part => part.tag !== 0x04)) throw new Error("Invalid seed/expanded key pair.");
        if (!equalBytes(impl.keygen(Uint8Array.from(parts[0].value)).secretKey, Uint8Array.from(parts[1].value))) throw new Error("Private-key seed does not match expanded key.");
        return new Key(scheme, type, parts[1].value);
    }
    throw new Error("Unsupported private-key encoding.");
}

function requireKey(key, type) {
    if (!(key instanceof Key) || key.type !== type) throw new Error("Wrong PQC key type.");
    return algorithm(key.asymmetricKeyType).impl;
}

const PQC = {
    backend: "bundled @noble/post-quantum 0.7.1",
    generateKeyPair: scheme => run(() => {
        const {impl} = algorithm(scheme);
        const {publicKey, secretKey} = impl.keygen(randomBytes(impl.lengths.seed));
        return {publicKey: new Key(scheme, "public", publicKey), privateKey: new Key(scheme, "private", secretKey)};
    }),
    createPublicKey: key => key instanceof Key
        ? new Key(key.asymmetricKeyType, "public", requireKey(key, "private").getPublicKey(key.bytes))
        : importKey(key, "public"),
    createPrivateKey: pem => importKey(pem, "private"),
    encapsulate: key => run(() => {
        const impl = requireKey(key, "public");
        const {cipherText, sharedSecret} = impl.encapsulate(key.bytes, randomBytes(impl.lengths.msgRand));
        return {ciphertext: Buffer.from(cipherText), sharedKey: Buffer.from(sharedSecret)};
    }),
    decapsulate: (key, ciphertext) => run(() => Buffer.from(requireKey(key, "private").decapsulate(Uint8Array.from(ciphertext), key.bytes))),
    sign: (data, key) => run(() => {
        const impl = requireKey(key, "private");
        return Buffer.from(impl.sign(Uint8Array.from(data), key.bytes, {extraEntropy: randomBytes(impl.lengths.signRand)}));
    }),
    verify: (data, key, signature) => run(() => requireKey(key, "public").verify(Uint8Array.from(signature), Uint8Array.from(data), key.bytes))
};

module.exports = {Crypto, PQC};
