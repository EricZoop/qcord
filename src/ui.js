"use strict";

module.exports = function createUI(R) {
    const h = R.createElement;
    const button = (label, onClick, props = {}) => h("button", {type: "button", onClick, ...props}, label);
    const field = (label, control) => h("label", {className: "qc-field"}, h("span", null, label), R.cloneElement(control, {"aria-label": control.props["aria-label"] || label}));
    const formula = text => h("div", {className: "qc-equation", role: "math"}, text);
    const code = text => h("code", {className: "qc-code"}, text);
    const p = text => h("p", null, text);
    function Tabs({items, value, onChange, label, disabled = false}) {
        const id = R.useId();
        return h("div", {role: "tablist", "aria-label": label, className: "qc-tabs"}, items.map(([key, name]) =>
            button(name, () => onChange(key), {key, role: "tab", id: `${id}-${key}`, "aria-selected": key === value, disabled,
                tabIndex: key === value ? 0 : -1, onKeyDown: event => {
                    const index = items.findIndex(([k]) => k === key);
                    const next = event.key === "ArrowRight" ? (index + 1) % items.length : event.key === "ArrowLeft" ? (index + items.length - 1) % items.length : event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : -1;
                    if (next < 0) return;
                    event.preventDefault(); onChange(items[next][0]); event.currentTarget.parentElement.children[next].focus();
                }})));
    }
    function Avatar({profile}) {
        const [failed, setFailed] = R.useState(false);
        R.useEffect(() => setFailed(false), [profile.avatar]);
        return profile.avatar && !failed
            ? h("img", {className: "qc-avatar", src: profile.avatar, alt: "", onError: () => setFailed(true)})
            : h("span", {className: "qc-avatar qc-avatar-fallback", "aria-hidden": true}, profile.displayName.slice(0, 1).toUpperCase());
    }
    function Polynomial({values, name, signed = false}) {
        const [index, setIndex] = R.useState(0);
        const i = Math.min(index, Math.max(0, values.length - 1));
        const scale = signed ? Math.max(1, ...values.map(Math.abs)) : 3328;
        return h("figure", {className: "qc-polynomial"},
            h("figcaption", null, h("strong", null, name), h("span", null, `${values.length} coefficients`)),
            h("svg", {viewBox: `0 0 640 ${Math.max(20, Math.ceil(values.length / 32) * 20)}`, role: "img", "aria-label": `${name}. Use the coefficient slider to inspect exact values.`},
                values.map((v, j) => h("rect", {key: j, x: j % 32 * 20 + 1, y: Math.floor(j / 32) * 20 + 1, width: 18, height: 18, rx: 2,
                    fill: v === 0 ? "var(--qc-empty)" : "var(--qc-graph)", opacity: j === i ? 1 : 0.3 + 0.7 * Math.min(1, Math.abs(v) / scale),
                    stroke: j === i ? "var(--qc-text)" : "none", strokeWidth: 2}, h("title", null, `${name}[${j}] = ${v}`)))),
            field("Coefficient index", h("input", {type: "range", min: 0, max: Math.max(0, values.length - 1), value: i, onChange: e => setIndex(Number(e.target.value))})),
            h("output", {className: "qc-equation", "aria-live": "polite"}, `a[${i}] = ${values[i] ?? 0}   →   ${values[i] ?? 0} · X^${i}`));
    }
    return {h, button, field, formula, code, p, Tabs, Avatar, Polynomial};
};
