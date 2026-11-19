"use strict";

// Educational reconstruction of public verification values. The acceptance
// decision always comes from noble's public ML-DSA.verify API.
const {shake128, shake256} = require("@noble/hashes/sha3.js");
const {encode, decode} = require("./mlkem");
const Q = 8380417, N = 256;
const presets = {
    "ml-kem-512": {label: "ML-DSA-44", k: 4, l: 4, gamma1: 2 ** 17, gamma2: (Q - 1) / 88, tau: 39, eta: 2, omega: 80, challengeBytes: 32},
    "ml-kem-768": {label: "ML-DSA-65", k: 6, l: 5, gamma1: 2 ** 19, gamma2: (Q - 1) / 32, tau: 49, eta: 4, omega: 55, challengeBytes: 48},
    "ml-kem-1024": {label: "ML-DSA-87", k: 8, l: 7, gamma1: 2 ** 19, gamma2: (Q - 1) / 32, tau: 60, eta: 2, omega: 75, challengeBytes: 64}
};
const parameters = scheme => {
    if (!Object.hasOwn(presets, scheme)) throw new Error("Unsupported signature parameter set.");
    return presets[scheme];
};
const mod = (x, q = Q) => ((x % q) + q) % q;
const concat = (...parts) => Uint8Array.from(parts.flatMap(part => Array.from(part)));
const blank = sigma => !sigma || sigma.c_tilde === "" && Array.isArray(sigma.z) && !sigma.z.length && Array.isArray(sigma.h) && !sigma.h.length;
function challengeBytes(text, size) {
    if (typeof text !== "string" || text.length !== 4 * Math.ceil(size / 3)) throw new Error("Invalid ML-DSA challenge length.");
    const bytes = Buffer.from(text, "base64");
    if (bytes.length !== size || bytes.toString("base64") !== text) throw new Error("Invalid ML-DSA challenge encoding.");
    return bytes;
}
function encodeSignature(sigma, scheme) {
    const p = parameters(scheme), d = p.gamma1 === 2 ** 17 ? 18 : 20;
    if (!sigma || Object.keys(sigma).sort().join() !== "c_tilde,h,z") throw new Error("Invalid ML-DSA signature fields.");
    const c = challengeBytes(sigma.c_tilde, p.challengeBytes);
    if (!Array.isArray(sigma.z) || sigma.z.length !== p.l || !sigma.z.every(poly => Array.isArray(poly) && poly.length === N && poly.every(x => Number.isInteger(x) && x > -p.gamma1 && x <= p.gamma1))) throw new Error("Invalid ML-DSA response vector.");
    if (!Array.isArray(sigma.h) || sigma.h.length !== p.k) throw new Error("Invalid ML-DSA hint vector.");
    const hints = new Uint8Array(p.omega + p.k);
    let count = 0;
    sigma.h.forEach((indices, i) => {
        if (!Array.isArray(indices) || !indices.every((x, j) => Number.isInteger(x) && x >= 0 && x < N && (!j || x > indices[j - 1])) || count + indices.length > p.omega) throw new Error("Invalid ML-DSA hint encoding.");
        hints.set(indices, count); count += indices.length; hints[p.omega + i] = count;
    });
    return concat(c, ...sigma.z.map(poly => encode(poly.map(x => p.gamma1 - x), d)), hints);
}
function decodeSignature(bytes, scheme) {
    const p = parameters(scheme), d = p.gamma1 === 2 ** 17 ? 18 : 20, width = d * 32;
    if (bytes.length !== p.challengeBytes + p.l * width + p.omega + p.k) throw new Error("Invalid ML-DSA signature length.");
    const offset = p.challengeBytes + p.l * width, hints = bytes.slice(offset);
    let count = 0;
    const sigma = {c_tilde: Buffer.from(bytes.slice(0, p.challengeBytes)).toString("base64"),
        z: Array.from({length: p.l}, (_, i) => decode(bytes.slice(p.challengeBytes + i * width, p.challengeBytes + (i + 1) * width), d).map(x => p.gamma1 - x)),
        h: Array.from({length: p.k}, (_, i) => { const end = hints[p.omega + i], indices = Array.from(hints.slice(count, end)); count = end; return indices; })};
    const canonical = encodeSignature(sigma, scheme);
    if (canonical.some((x, i) => x !== bytes[i])) throw new Error("Noncanonical ML-DSA signature.");
    return sigma;
}
function pow(a, n) { let r = 1; for (; n; n = Math.floor(n / 2), a = mod(a * a)) if (n % 2) r = mod(r * a); return r; }
const zetas = Array.from({length: N}, (_, i) => pow(1753, parseInt(i.toString(2).padStart(8, "0").split("").reverse().join(""), 2)));
function ntt(input, inverse = false) {
    const f = Array.from(input, x => mod(x)); let k = inverse ? 255 : 1;
    for (let len = inverse ? 1 : 128; inverse ? len <= 128 : len >= 1; len = inverse ? len * 2 : len / 2) {
        for (let start = 0; start < N; start += 2 * len) {
            const z = zetas[inverse ? k-- : k++];
            for (let j = start; j < start + len; j++) {
                const t = f[j];
                if (inverse) { f[j] = mod(t + f[j + len]); f[j + len] = mod(z * (f[j + len] - t)); }
                else { const u = mod(z * f[j + len]); f[j] = mod(t + u); f[j + len] = mod(t - u); }
            }
        }
    }
    return inverse ? f.map(x => mod(x * 8347681)) : f; // 256^-1 modulo q
}
function sampleMatrix(rho, i, j) {
    const xof = shake128.create().update(concat(rho, [j, i])), out = [];
    while (out.length < N) {
        const b = xof.xof(168);
        for (let n = 0; n < b.length && out.length < N; n += 3) { const x = (b[n] | b[n + 1] << 8 | b[n + 2] << 16) & 0x7fffff; if (x < Q) out.push(x); }
    }
    xof.destroy(); return out;
}
function sampleChallenge(seed, tau) {
    const xof = shake256.create().update(seed); let block = xof.xof(136), pos = 8;
    const signs = block.slice(0, 8), c = Array(N).fill(0);
    const next = () => { if (pos === block.length) { block = xof.xof(136); pos = 0; } return block[pos++]; };
    for (let i = N - tau, bit = 0; i < N; i++, bit++) {
        let b; do { b = next(); } while (b > i);
        c[i] = c[b]; c[b] = 1 - 2 * ((signs[bit >> 3] >> (bit % 8)) & 1);
    }
    xof.destroy(); return c;
}
function useHint(value, hint, gamma2) {
    const alpha = 2 * gamma2, r = mod(value), low = mod(r, alpha);
    let r0 = low > gamma2 ? low - alpha : low, r1;
    if (r - r0 === Q - 1) { r1 = 0; r0--; } else r1 = (r - r0) / alpha;
    return hint ? mod(r1 + (r0 > 0 ? 1 : -1), (Q - 1) / alpha) : r1;
}
function verificationTrace(publicKey, payload, sigma, scheme) {
    const p = parameters(scheme);
    encodeSignature(sigma, scheme);
    if (publicKey.length !== 32 + 320 * p.k) throw new Error("Invalid ML-DSA public key length.");
    const rho = publicKey.slice(0, 32), t1 = Array.from({length: p.k}, (_, i) => decode(publicKey.slice(32 + i * 320, 32 + (i + 1) * 320), 10));
    const tr = shake256(publicKey, {dkLen: 64}), mu = shake256(concat(tr, [0, 0], payload), {dkLen: 64});
    const c = sampleChallenge(challengeBytes(sigma.c_tilde, p.challengeBytes), p.tau), cHat = ntt(c), zHat = sigma.z.map(poly => ntt(poly));
    const wApprox = [], w1 = [];
    for (let i = 0; i < p.k; i++) {
        const sum = Array(N).fill(0);
        for (let j = 0; j < p.l; j++) { const a = sampleMatrix(rho, i, j); for (let n = 0; n < N; n++) sum[n] = mod(sum[n] + mod(a[n] * zHat[j][n])); }
        const t = ntt(t1[i].map(x => x * 8192));
        const w = ntt(sum.map((x, n) => mod(x - mod(cHat[n] * t[n]))), true), hints = new Set(sigma.h[i]);
        wApprox.push(w); w1.push(w.map((x, n) => useHint(x, hints.has(n), p.gamma2)));
    }
    const computed = shake256(concat(mu, ...w1.map(poly => encode(poly, p.gamma2 === (Q - 1) / 88 ? 6 : 4))), {dkLen: p.challengeBytes});
    return {rho, t1, tr, mu, c, wApprox, w1, computed: Buffer.from(computed).toString("base64"), expected: sigma.c_tilde,
        zNorm: Math.max(...sigma.z.flat().map(Math.abs)), zBound: p.gamma1 - p.tau * p.eta, hintCount: sigma.h.reduce((n, h) => n + h.length, 0), hintBound: p.omega, ...p};
}
module.exports = {parameters, blank, encodeSignature, decodeSignature, verificationTrace, ntt, Q};
