"use strict";

const {ml_kem512} = require("@noble/post-quantum/ml-kem.js");
const {equalBytes} = require("@noble/post-quantum/utils.js");
const {pack, unpack, readKeyData} = require("./der");

// NIST identifier for ML-KEM-512 SPKI / PKCS#8 keys.
const algorithms = {
    "ml-kem-512": {impl: ml_kem512, oid: "608648016503040401"}
};

function algorithm(scheme) {
    if (!Object.hasOwn(algorithms, scheme)) throw new Error("Unsupported PQC algorithm.");
    return algorithms[scheme];
}

function randomBytes(size) {
    if (!globalThis.crypto?.getRandomValues) throw new Error("Secure browser randomness is unavailable. Reload Discord.");
    return globalThis.crypto.getRandomValues(new Uint8Array(size));
}

// Yield before bounded PQC operations so status updates can render.
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
        if (type !== (privateKey ? "pkcs8" : "spki") || !["der", "base64"].includes(format)) throw new Error("Unsupported key export format.");
        const identifier = pack(0x30, pack(0x06, Buffer.from(algorithm(this.asymmetricKeyType).oid, "hex")));
        // RFC 9935 expanded-key CHOICE.
        const body = pack(0x04, this.bytes);
        const der = privateKey
            ? pack(0x30, pack(0x02, Buffer.from([0])), identifier, pack(0x04, body))
            : pack(0x30, identifier, pack(0x03, Buffer.from([0]), this.bytes));
        return format === "der" ? der : der.toString("base64");
    }
}

function importKey(text, type) {
    const top = unpack(readKeyData(text));
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
    algorithm(scheme);
    if (type === "public") {
        if (data.tag !== 0x03 || data.value[0] !== 0) throw new Error("Invalid public-key bit string.");
        return new Key(scheme, type, data.value.subarray(1));
    }
    if (data.tag !== 0x04) throw new Error("Invalid private-key octet string.");
    const choice = unpack(data.value);
    if (choice.length !== 1) throw new Error("Invalid private-key encoding.");
    const {tag, value} = choice[0];
    if (tag === 0x04) return new Key(scheme, type, value);
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
    createPrivateKey: text => importKey(text, "private"),
    encapsulate: key => run(() => {
        const impl = requireKey(key, "public");
        const {cipherText, sharedSecret} = impl.encapsulate(key.bytes, randomBytes(impl.lengths.msgRand));
        return {ciphertext: Buffer.from(cipherText), sharedKey: Buffer.from(sharedSecret)};
    }),
    decapsulate: (key, ciphertext) => run(() => Buffer.from(requireKey(key, "private").decapsulate(Uint8Array.from(ciphertext), key.bytes)))
};

module.exports = {PQC, randomBytes, equalBytes};
