"use strict";

// Read-only educational arithmetic. Packet cryptography always uses noble's public
// ML-KEM API. A trace must reproduce its ciphertext byte for byte before display.
const {sha3_256, sha3_512, shake128, shake256} = require("@noble/hashes/sha3.js");
const {parameters} = require("./parameters");
const {ACTIVE_SCHEME} = require("./constants");
const Q = 3329, N = 256;
const mod = n => ((n % Q) + Q) % Q;
const concat = (...arrays) => Uint8Array.from(arrays.flatMap(a => Array.from(a)));
const bits = bytes => Array.from(bytes).flatMap(b => Array.from({length: 8}, (_, i) => (b >> i) & 1));
const compress = (x, d) => Math.floor((mod(x) * 2 ** d + 1664) / Q) % 2 ** d;
const decompress = (x, d) => Math.floor((Q * x + 2 ** (d - 1)) / 2 ** d);
const add = (a, b) => a.map((v, i) => mod(v + b[i]));
const sub = (a, b) => a.map((v, i) => mod(v - b[i]));
const centered = x => x > 1664 ? x - Q : x;
function decode(bytes, d) {
    const stream = bits(bytes);
    return Array.from({length: N}, (_, i) => {
        let v = 0;
        for (let j = 0; j < d; j++) v += stream[i * d + j] * 2 ** j;
        return v;
    });
}
function encode(values, d) {
    const out = new Uint8Array(values.length * d / 8);
    values.forEach((v, i) => {
        for (let j = 0; j < d; j++) out[(i * d + j) >> 3] |= ((v >> j) & 1) << ((i * d + j) % 8);
    });
    return out;
}
function pow(a, n) { let v = 1; for (; n; n >>= 1, a = mod(a * a)) if (n & 1) v = mod(v * a); return v; }
const reverse7 = n => parseInt(n.toString(2).padStart(7, "0").split("").reverse().join(""), 2);
const zetas = Array.from({length: 128}, (_, i) => pow(17, reverse7(i)));
function ntt(input, inverse = false) {
    const f = Array.from(input);
    let k = inverse ? 127 : 1;
    for (let len = inverse ? 2 : 128; inverse ? len <= 128 : len >= 2; len = inverse ? len * 2 : len / 2) {
        for (let start = 0; start < N; start += 2 * len) {
            const z = zetas[inverse ? k-- : k++];
            for (let j = start; j < start + len; j++) {
                const t = f[j];
                if (inverse) {
                    f[j] = mod(t + f[j + len]);
                    f[j + len] = mod(z * (f[j + len] - t));
                } else {
                    const u = mod(z * f[j + len]);
                    f[j] = mod(t + u); f[j + len] = mod(t - u);
                }
            }
        }
    }
    return inverse ? f.map(v => mod(v * 3303)) : f;
}
function multiply(a, b) {
    const out = [];
    for (let i = 0; i < 128; i++) {
        const j = 2 * i, gamma = pow(17, 2 * reverse7(i) + 1);
        out.push(mod(a[j] * b[j] + mod(a[j + 1] * b[j + 1]) * gamma));
        out.push(mod(a[j] * b[j + 1] + a[j + 1] * b[j]));
    }
    return out;
}
const dot = (a, b) => a.reduce((sum, poly, i) => add(sum, multiply(poly, b[i])), Array(N).fill(0));
function sampleNTT(rho, i, j) {
    // Final FIPS 203: A-hat[i,j] = SampleNTT(rho || byte(j) || byte(i)).
    const xof = shake128.create().update(concat(rho, [j, i]));
    const out = [];
    while (out.length < N) {
        const block = xof.xof(168);
        for (let p = 0; p < block.length && out.length < N; p += 3) {
            const d1 = block[p] + 256 * (block[p + 1] & 15);
            const d2 = (block[p + 1] >> 4) + 16 * block[p + 2];
            if (d1 < Q) out.push(d1);
            if (d2 < Q && out.length < N) out.push(d2);
        }
    }
    xof.destroy();
    return out;
}
function cbd(seed, nonce, eta) {
    const stream = bits(shake256(concat(seed, [nonce]), {dkLen: 64 * eta}));
    return Array.from({length: N}, (_, i) => {
        let sum = 0;
        for (let j = 0; j < eta; j++) sum += stream[2*eta*i+j] - stream[2*eta*i+eta+j];
        return mod(sum);
    });
}
function publicTrace(ek, scheme = ACTIVE_SCHEME) {
    const {k, publicBytes} = parameters(scheme);
    if (ek.length !== publicBytes) throw new Error("Public key does not match the selected parameter set.");
    const rho = ek.slice(384*k);
    const tHat = Array.from({length: k}, (_, i) => decode(ek.slice(i * 384, (i+1) * 384), 12));
    const aHat = Array.from({length: k}, (_, i) => Array.from({length: k}, (_, j) => sampleNTT(rho, i, j)));
    return {rho, tHat, aHat};
}
function encapsulationTrace(ek, m, ciphertext, scheme = ACTIVE_SCHEME) {
    const {k, eta1, eta2, du, dv} = parameters(scheme);
    const pub = publicTrace(ek, scheme);
    const kr = sha3_512(concat(m, sha3_256(ek)));
    const r = kr.slice(32);
    const rVector = Array.from({length: k}, (_, i) => cbd(r, i, eta1));
    const rHat = rVector.map(p => ntt(p));
    const e1 = Array.from({length: k}, (_, i) => cbd(r, k+i, eta2));
    const e2 = cbd(r, 2*k, eta2);
    const mu = bits(m).map(b => decompress(b, 1));
    const u = e1.map((e, i) => add(ntt(dot(pub.aHat.map(row => row[i]), rHat), true), e));
    const v = add(add(ntt(dot(pub.tHat, rHat), true), e2), mu);
    const packed = concat(...u.map(p => encode(p.map(x => compress(x, du)), du)), encode(v.map(x => compress(x, dv)), dv));
    kr.fill(0); r.fill(0);
    if (packed.length !== ciphertext.length || packed.some((b, i) => b !== ciphertext[i])) throw new Error("The polynomial trace did not match ML-KEM. No preview was produced.");
    return {...pub, m: Uint8Array.from(m), mu, rVector: rVector.map(p => p.map(centered)), e1: e1.map(p => p.map(centered)), e2: e2.map(centered), u, v, ciphertext: Uint8Array.from(ciphertext)};
}
function decapsulationTrace(dk, ciphertext, scheme = ACTIVE_SCHEME) {
    const {k, du, dv} = parameters(scheme);
    const width = 32*du;
    const sHat = Array.from({length: k}, (_, i) => decode(dk.slice(i*384, (i+1)*384), 12));
    const u = Array.from({length: k}, (_, i) => decode(ciphertext.slice(i*width, (i+1)*width), du).map(x => decompress(x, du)));
    const v = decode(ciphertext.slice(k*width), dv).map(x => decompress(x, dv));
    const w = sub(v, ntt(dot(sHat, u.map(p => ntt(p))), true));
    return {u, v, w, m: encode(w.map(x => compress(x, 1)), 1)};
}
// Remove reachable numeric buffers when a preview is invalidated or closed.
// JavaScript strings/GC copies cannot be reliably zeroized.
function wipe(value) {
    if (ArrayBuffer.isView(value)) value.fill(0);
    else if (Array.isArray(value)) { value.forEach(wipe); value.fill(0); }
    else if (value && typeof value === "object") Object.values(value).forEach(wipe);
}
module.exports = {Q, N, mod, bits, compress, decompress, ntt, multiply, encode, decode, publicTrace, encapsulationTrace, decapsulationTrace, wipe};
