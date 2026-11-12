/*
 * On-screen keyboard for the touchscreen kiosk.
 * Self-contained: injects its own styles and markup, then attaches to every
 * text/password input on the page. Opens on focus, writes into the focused
 * field, closes on Done or when tapping outside. Sized for the 480x320
 * resistive panel (large keys).
 *
 * To enable on a page, add before </body>:
 *   <script src="/static/keyboard.js"></script>
 */
(function () {
  "use strict";

  var LAYERS = {
    abc: [
      ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
      ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
      ["a", "s", "d", "f", "g", "h", "j", "k", "l"],
      ["shift", "z", "x", "c", "v", "b", "n", "m", "back"],
      ["sym", "space", "done"]
    ],
    sym: [
      ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
      ["@", "#", "$", "%", "&", "*", "-", "_", "+", "="],
      ["!", "?", ".", ",", ":", ";", "/", "(", ")"],
      ["abc", "'", "\"", "<", ">", "[", "]", "{", "back"],
      ["abc", "space", "done"]
    ]
  };

  var WIDE = { space: 1, done: 1, shift: 1, back: 1, sym: 1, abc: 1 };
  var LABEL = {
    shift: "⇧", back: "⌫", space: " ", done: "Done",
    sym: "?123", abc: "ABC"
  };

  var target = null;      // the input being edited
  var layer = "abc";
  var upper = false;
  var kb, preview, rowsBox;

  function css() {
    if (document.getElementById("fk-style")) return;
    var s = document.createElement("style");
    s.id = "fk-style";
    s.textContent =
      "#fk{position:fixed;left:0;right:0;bottom:0;z-index:99999;" +
      "background:#161b22;border-top:1px solid #30363d;" +
      "padding:4px;box-sizing:border-box;font-family:system-ui,sans-serif;" +
      "user-select:none;-webkit-user-select:none;touch-action:manipulation;}" +
      "#fk.fk-hidden{display:none;}" +
      "#fk .fk-top{display:flex;align-items:center;gap:6px;padding:2px 4px 6px;}" +
      "#fk .fk-prev{flex:1;background:#0d1117;border:1px solid #30363d;" +
      "border-radius:6px;color:#e6edf3;font-size:15px;padding:5px 8px;" +
      "min-height:20px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}" +
      "#fk .fk-eye{background:#21262d;border:1px solid #30363d;border-radius:6px;" +
      "color:#e6edf3;font-size:15px;padding:5px 9px;cursor:pointer;}" +
      "#fk .fk-row{display:flex;gap:4px;margin-bottom:4px;justify-content:center;}" +
      "#fk .fk-key{flex:1;background:#21262d;border:1px solid #30363d;" +
      "border-radius:6px;color:#e6edf3;font-size:16px;line-height:1;" +
      "padding:9px 0;text-align:center;cursor:pointer;}" +
      "#fk .fk-key:active{background:#30363d;}" +
      "#fk .fk-key.fk-wide{flex:1.6;}" +
      "#fk .fk-key.fk-space{flex:4;}" +
      "#fk .fk-key.fk-act{background:#238636;border-color:#2ea043;font-weight:600;}" +
      "#fk .fk-key.fk-on{background:#1f6feb;border-color:#388bfd;}";
    document.head.appendChild(s);
  }

  function build() {
    kb = document.createElement("div");
    kb.id = "fk";
    kb.className = "fk-hidden";

    var top = document.createElement("div");
    top.className = "fk-top";
    preview = document.createElement("div");
    preview.className = "fk-prev";
    var eye = document.createElement("button");
    eye.className = "fk-eye";
    eye.type = "button";
    eye.textContent = "\u{1F441}";
    eye.addEventListener("mousedown", function (e) {
      e.preventDefault();
      if (!target) return;
      target.type = target.type === "password" ? "text" : "password";
    });
    top.appendChild(preview);
    top.appendChild(eye);
    kb.appendChild(top);

    rowsBox = document.createElement("div");
    kb.appendChild(rowsBox);
    document.body.appendChild(kb);

    // Keep taps on the keyboard from blurring the field.
    kb.addEventListener("mousedown", function (e) { e.preventDefault(); });
    kb.addEventListener("touchstart", function (e) {
      if (e.target === kb || e.target === rowsBox || e.target.className === "fk-top") {
        e.preventDefault();
      }
    }, { passive: false });
  }

  function render() {
    rowsBox.innerHTML = "";
    LAYERS[layer].forEach(function (row) {
      var r = document.createElement("div");
      r.className = "fk-row";
      row.forEach(function (k) {
        var b = document.createElement("div");
        b.className = "fk-key";
        if (k === "space") b.className += " fk-space";
        else if (WIDE[k]) b.className += " fk-wide";
        if (k === "done") b.className += " fk-act";
        if (k === "shift" && upper) b.className += " fk-on";

        if (LABEL[k] !== undefined) {
          b.textContent = LABEL[k];
        } else {
          b.textContent = upper ? k.toUpperCase() : k;
        }
        b.addEventListener("mousedown", function (e) {
          e.preventDefault();
          press(k);
        });
        r.appendChild(b);
      });
      rowsBox.appendChild(r);
    });
  }

  function refreshPreview() {
    if (!target) return;
    preview.textContent = target.value || "";
  }

  function insert(ch) {
    if (!target) return;
    var s = target.selectionStart, e = target.selectionEnd;
    if (s === null || s === undefined) {
      target.value += ch;
    } else {
      target.value = target.value.slice(0, s) + ch + target.value.slice(e);
      var p = s + ch.length;
      try { target.setSelectionRange(p, p); } catch (x) {}
    }
    target.dispatchEvent(new Event("input", { bubbles: true }));
    refreshPreview();
  }

  function backspace() {
    if (!target) return;
    var s = target.selectionStart, e = target.selectionEnd;
    if (s === null || s === undefined) {
      target.value = target.value.slice(0, -1);
    } else if (s !== e) {
      target.value = target.value.slice(0, s) + target.value.slice(e);
      try { target.setSelectionRange(s, s); } catch (x) {}
    } else if (s > 0) {
      target.value = target.value.slice(0, s - 1) + target.value.slice(s);
      try { target.setSelectionRange(s - 1, s - 1); } catch (x) {}
    }
    target.dispatchEvent(new Event("input", { bubbles: true }));
    refreshPreview();
  }

  function press(k) {
    switch (k) {
      case "shift": upper = !upper; render(); break;
      case "back": backspace(); break;
      case "space": insert(" "); break;
      case "sym": layer = "sym"; upper = false; render(); break;
      case "abc": layer = "abc"; render(); break;
      case "done": hide(); break;
      default:
        insert(upper ? k.toUpperCase() : k);
        if (upper && layer === "abc") { upper = false; render(); }
    }
  }

  function show(input) {
    target = input;
    layer = "abc";
    upper = false;
    render();
    refreshPreview();
    kb.classList.remove("fk-hidden");
  }

  function hide() {
    kb.classList.add("fk-hidden");
    if (target) { try { target.blur(); } catch (x) {} }
    target = null;
  }

  function wanted(el) {
    if (!el || el.tagName !== "INPUT" && el.tagName !== "TEXTAREA") return false;
    if (el.tagName === "INPUT") {
      var t = (el.type || "text").toLowerCase();
      if (["hidden", "checkbox", "radio", "submit", "button", "file",
           "range", "color", "date"].indexOf(t) !== -1) return false;
    }
    if (el.readOnly || el.disabled) return false;
    return true;
  }

  function init() {
    css();
    build();
    document.addEventListener("focusin", function (e) {
      if (wanted(e.target)) {
        // Suppress any native on-screen keyboard; use ours only.
        e.target.setAttribute("inputmode", "none");
        show(e.target);
      }
    });
    // Tap outside a field and outside the keyboard closes it.
    // Test by geometry, not kb.contains(e.target): tapping a key can rebuild
    // the rows (shift / layer change) and detach the tapped element, which
    // would then look "outside" and wrongly close the keyboard.
    document.addEventListener("mousedown", function (e) {
      if (!kb || kb.classList.contains("fk-hidden")) return;
      var r = kb.getBoundingClientRect();
      if (e.clientX >= r.left && e.clientX <= r.right &&
          e.clientY >= r.top && e.clientY <= r.bottom) return;
      if (wanted(e.target)) return;
      hide();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
