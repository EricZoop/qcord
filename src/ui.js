"use strict";

const {filled} = require("./icons");

module.exports = function createUI(R) {
    const h = R.createElement;
    const button = (label, onClick, props = {}) => h("button", {type: "button", onClick, ...props}, label);
    const field = (label, control) => h("label", {className: "qc-field"}, h("span", null, label), R.cloneElement(control, {"aria-label": control.props["aria-label"] || label}));
    const formula = text => h("div", {className: "qc-equation", role: "math"}, text);
    const code = text => h("code", {className: "qc-code"}, text);
    const p = text => h("p", null, text);
    function Icon({name}) {
        const icon = filled[name];
        if (!icon) throw new Error(`Unknown Qcord icon: ${name}`);
        return h("svg", {viewBox: icon.viewBox, width: 14, height: 14, fill: "currentColor", "aria-hidden": true}, h("path", {d: icon.path}));
    }
    function Tabs({items, value, onChange, label, disabled = false}) {
        const id = R.useId();
        return h("div", {role: "tablist", "aria-label": label, className: "qc-tabs"}, items.map(([key, name]) => button(name, () => onChange(key), {
            key, role: "tab", id: `${id}-${key}`, "aria-selected": key === value, tabIndex: key === value ? 0 : -1, disabled,
            onKeyDown: event => {
                const i = items.findIndex(([k]) => k === key);
                const next = event.key === "ArrowRight" ? (i + 1) % items.length : event.key === "ArrowLeft" ? (i + items.length - 1) % items.length : event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : -1;
                if (next >= 0) { event.preventDefault(); onChange(items[next][0]); event.currentTarget.parentElement.children[next].focus(); }
            }
        })));
    }
    function Switch({label, checked, onChange, disabled, title}) {
        return button(h(R.Fragment, null, h("span", null, label), h("span", {className: "qc-switch-track"}, h("span"))), () => onChange(!checked), {className: "qc-switch", role: "switch", "aria-label": label, "aria-checked": checked, disabled, title});
    }
    function Avatar({profile}) {
        const [failed, setFailed] = R.useState(false);
        R.useEffect(() => setFailed(false), [profile.avatar]);
        return profile.avatar && !failed ? h("img", {className: "qc-avatar", src: profile.avatar, alt: "", onError: () => setFailed(true)}) : h("span", {className: "qc-avatar qc-avatar-fallback", "aria-hidden": true}, profile.displayName.slice(0, 1).toUpperCase());
    }
    function Variables({items}) {
        return h("dl", {className: "qc-variables", "aria-label": "Known variables"}, items.map(([symbol, value]) => h("div", {key: symbol}, h("dt", null, symbol), h("dd", null, value))));
    }
    function Sparkline({values = []}) {
        const min = Math.min(0, ...values), max = Math.max(1, ...values), span = Math.max(1, max - min);
        const points = values.filter((_, i) => i % 4 === 0).map((v, i, a) => `${i / Math.max(1, a.length - 1) * 100},${25 - (v - min) / span * 23}`).join(" ");
        return h("svg", {viewBox: "0 0 100 28", preserveAspectRatio: "none", "aria-hidden": true}, h("polyline", {points, fill: "none", stroke: "currentColor", strokeWidth: 1.2}));
    }
    function KeyParts() {
        return h("div", {className: "qc-keyparts", "aria-label": "Public key byte order"}, h("div", null, h("strong", null, "Encoded t̂"), h("span", null, "1152 bytes · 1536 Base64 characters")), h("div", null, h("strong", null, "ρ seed"), h("span", null, "32 bytes · 44 Base64 characters")));
    }
    function Polynomial({values, name, signed = false, index, onIndexChange}) {
        const [localIndex, setLocalIndex] = R.useState(0);
        const dragging = R.useRef(false);
        const frame = R.useRef(null), pendingIndex = R.useRef(0);
        R.useEffect(() => () => { if (frame.current !== null) cancelAnimationFrame(frame.current); }, []);
        const i = Math.min(index ?? localIndex, Math.max(0, values.length - 1));
        const choose = value => { if (index === undefined) setLocalIndex(value); onIndexChange?.(value); };
        const baseline = signed ? 58 : 110;
        const bars = R.useMemo(() => {
            const scale = signed ? Math.max(1, ...values.map(Math.abs)) : 3328;
            return values.map((v, j) => { const height = Math.max(1, Math.abs(v) / scale * (signed ? 50 : 100)); return h("rect", {key: j, x: j * 2.5, y: signed && v < 0 ? baseline : baseline - height, width: 1.8, height, fill: "var(--qc-graph)", opacity: .7}, h("title", null, `${name}[${j}] = ${v}`)); });
        }, [values, signed, name]);
        const scrub = (event, immediate = false) => {
            const rect = event.currentTarget.getBoundingClientRect();
            pendingIndex.current = Math.max(0, Math.min(values.length - 1, Math.floor((event.clientX - rect.left) / rect.width * values.length)));
            if (immediate) {
                if (frame.current !== null) cancelAnimationFrame(frame.current);
                frame.current = null; choose(pendingIndex.current);
            } else if (frame.current === null) {
                frame.current = requestAnimationFrame(() => { frame.current = null; choose(pendingIndex.current); });
            }
        };
        const cancelDrag = () => { dragging.current = false; if (frame.current !== null) cancelAnimationFrame(frame.current); frame.current = null; };
        return h("figure", {className: "qc-polynomial"},
            h("figcaption", null, h("strong", null, name), h("span", null, `${values.length} coefficients`)),
            h("svg", {viewBox: "0 0 640 120", role: "img", "aria-label": `${name}. Click or drag to inspect coefficients.`,
                onPointerDown: event => { if (event.button !== 0) return; event.preventDefault(); dragging.current = true; event.currentTarget.setPointerCapture(event.pointerId); scrub(event, true); },
                onPointerMove: event => { if (dragging.current) scrub(event); },
                onPointerUp: event => { if (dragging.current) { scrub(event, true); dragging.current = false; event.currentTarget.releasePointerCapture(event.pointerId); } },
                onPointerCancel: cancelDrag, onLostPointerCapture: cancelDrag
            }, h("line", {x1: 0, x2: 640, y1: baseline, y2: baseline, stroke: "currentColor", opacity: .15}), bars,
                h("line", {className: "qc-selection", style: {transform: `translateX(${i * 2.5 + .9}px)`}, x1: 0, x2: 0, y1: 5, y2: 113, stroke: "var(--qc-text)", strokeWidth: 1.2, opacity: .8, pointerEvents: "none"})),
            h("div", {className: "qc-scrubber"}, field("Coefficient index", h("input", {type: "range", min: 0, max: values.length - 1, value: i, "aria-valuetext": `Coefficient ${i}: ${values[i] ?? 0}`, style: {"--qc-progress": `${i / Math.max(1, values.length - 1) * 100}%`}, onChange: e => choose(Number(e.target.value))}))),
            h("div", {className: "qc-coefficient-strip", "aria-label": "Nearby coefficients"}, Array.from({length: 7}, (_, j) => Math.max(0, Math.min(values.length - 7, i - 3)) + j).filter(j => j < values.length).map(j => button(h(R.Fragment, null, h("small", null, j), values[j]), () => choose(j), {key: j, "aria-pressed": j === i, title: `Coefficient ${j}`}))));
    }
    return {h, button, field, formula, code, p, Icon, Tabs, Switch, Avatar, Variables, Sparkline: R.memo(Sparkline), KeyParts, Polynomial: R.memo(Polynomial)};
};
