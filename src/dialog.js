"use strict";

// Native dialogs keep Escape/focus handling; backdrop dismissal ignores drags that
// began inside a panel, including coefficient sliders and text selection.
module.exports = function dismissOnBackdrop(dialog, dismiss) {
    const outside = event => {
        const rect = dialog.getBoundingClientRect();
        return event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom);
    };
    let pressedOutside = false;
    const down = event => { pressedOutside = outside(event); };
    const up = event => { if (pressedOutside && outside(event)) dismiss(); pressedOutside = false; };
    dialog.addEventListener("pointerdown", down);
    dialog.addEventListener("pointerup", up);
    return () => { dialog.removeEventListener("pointerdown", down); dialog.removeEventListener("pointerup", up); };
};
