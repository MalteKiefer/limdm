// Visual editor for blueprint assignment maps. Builds the DOM with
// createElement/textContent only (no innerHTML), keeps the JSON in the form's
// textarea in sync, and leaves validation to the server.
(function () {
  "use strict";
  const root = document.getElementById("bp-editor");
  const field = document.getElementById("bp-tree");
  if (!root || !field) return;

  const items = JSON.parse(document.getElementById("bp-items").textContent || "[]") || [];
  const fields = JSON.parse(document.getElementById("bp-fields").textContent || "{}") || {};
  const byId = new Map(items.map((it) => [it.id, it]));
  const fieldLabels = {
    "os.id": "Distribution", "os.version": "OS version", arch: "Architecture", desktop: "Desktop",
    vendor: "Vendor", model: "Model", hostname: "Hostname", tag: "Tag", group: "Directory group", department: "Department",
  };
  const opLabels = {
    eq: "is", ne: "is not", gte: "at least", lte: "at most", contains: "contains", present: "is installed",
    absent: "is not installed", glob: "matches", has: "has", not_has: "does not have", member: "is member of", not_member: "is not member of",
  };
  const noValue = new Set(["present", "absent"]);

  let tree;
  try { tree = JSON.parse(field.value || "[]"); } catch (e) { return; } // keep the JSON fallback
  if (!Array.isArray(tree)) return;

  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const button = (label, cls, onClick) => {
    const b = el("button", "secondary small " + (cls || ""), label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  };
  const sync = () => { field.value = JSON.stringify(tree, null, 2); };
  const rerender = () => { sync(); render(); };

  function itemSelect(onPick) {
    const s = el("select", "small");
    s.setAttribute("aria-label", "Add library item");
    s.appendChild(new Option("Add library item…", ""));
    const groups = {};
    for (const it of items) (groups[it.type] = groups[it.type] || []).push(it);
    for (const type of Object.keys(groups).sort()) {
      const g = document.createElement("optgroup");
      g.label = type.replace("com.limdm.", "");
      for (const it of groups[type]) g.appendChild(new Option(it.name, String(it.id)));
      s.appendChild(g);
    }
    s.addEventListener("change", () => { if (s.value) onPick(Number(s.value)); });
    return s;
  }

  function ruleRow(rules, i) {
    const r = rules[i];
    const row = el("div", "bp-rule");
    const f = el("select", "small");
    for (const name of Object.keys(fields)) f.appendChild(new Option(fieldLabels[name] || name, name));
    f.value = r.field;
    f.addEventListener("change", () => { r.field = f.value; r.op = fields[r.field][0]; rerender(); });
    const o = el("select", "small");
    for (const op of fields[r.field] || []) o.appendChild(new Option(opLabels[op] || op, op));
    o.value = r.op;
    o.addEventListener("change", () => { r.op = o.value; rerender(); });
    row.append(f, o);
    if (!noValue.has(r.op)) {
      const v = el("input", "small");
      v.value = r.value || "";
      v.placeholder = r.field === "os.id" ? "debian, ubuntu, fedora" : r.field === "hostname" ? "ws-*" : "value";
      v.setAttribute("aria-label", "Rule value");
      v.addEventListener("input", () => { r.value = v.value; sync(); });
      row.append(v);
    }
    row.append(button("Remove", "ghost", () => { rules.splice(i, 1); rerender(); }));
    return row;
  }

  function nodeList(nodes, depth) {
    const wrap = el("div", "bp-list");
    nodes.forEach((n, i) => wrap.appendChild(nodeCard(nodes, i, depth)));
    const add = el("div", "bp-add");
    add.append(
      button("+ Assign items", "", () => { nodes.push({ kind: "assign", items: [] }); rerender(); }),
      button("+ Condition", "", () => {
        nodes.push({ kind: "if", branches: [{ match: "all", rules: [{ field: "os.id", op: "eq", value: "" }], nodes: [] }], else: [] });
        rerender();
      }),
    );
    wrap.appendChild(add);
    return wrap;
  }

  function moveControls(nodes, i) {
    const c = el("div", "bp-move");
    if (i > 0) c.append(button("↑", "ghost", () => { [nodes[i - 1], nodes[i]] = [nodes[i], nodes[i - 1]]; rerender(); }));
    if (i < nodes.length - 1) c.append(button("↓", "ghost", () => { [nodes[i + 1], nodes[i]] = [nodes[i], nodes[i + 1]]; rerender(); }));
    c.append(button("Delete", "ghost danger", () => { nodes.splice(i, 1); rerender(); }));
    return c;
  }

  function nodeCard(nodes, i, depth) {
    const n = nodes[i];
    const card = el("div", "bp-node bp-" + n.kind);
    const head = el("div", "bp-head");
    head.append(el("span", "bp-kind", n.kind === "assign" ? "Assign" : "Condition"), moveControls(nodes, i));
    card.appendChild(head);
    if (n.kind === "assign") {
      n.items = n.items || [];
      const chips = el("div", "bp-chips");
      n.items.forEach((id, k) => {
        const it = byId.get(id);
        const chip = el("span", "bp-chip");
        chip.append(el("b", "", it ? it.name : "missing item " + id), el("small", "", it ? it.type.replace("com.limdm.", "") : ""));
        const x = button("×", "ghost", () => { n.items.splice(k, 1); rerender(); });
        x.setAttribute("aria-label", "Remove item");
        chip.append(x);
        chips.appendChild(chip);
      });
      if (!n.items.length) chips.appendChild(el("span", "muted", "No items yet."));
      card.append(chips, itemSelect((id) => { if (!n.items.includes(id)) n.items.push(id); rerender(); }));
      return card;
    }
    n.branches.forEach((b, k) => {
      const br = el("div", "bp-branch");
      const bh = el("div", "bp-branch-head");
      const match = el("select", "small");
      match.append(new Option("all rules match", "all"), new Option("any rule matches", "any"));
      match.value = b.match;
      match.addEventListener("change", () => { b.match = match.value; sync(); });
      bh.append(el("span", "bp-cond", k === 0 ? "If" : "Else if"), match);
      if (n.branches.length > 1) bh.append(button("Remove branch", "ghost", () => { n.branches.splice(k, 1); rerender(); }));
      br.appendChild(bh);
      b.rules.forEach((_, r) => br.appendChild(ruleRow(b.rules, r)));
      br.append(button("+ Rule", "ghost", () => { b.rules.push({ field: "os.id", op: "eq", value: "" }); rerender(); }));
      const then = el("div", "bp-then");
      then.append(el("span", "bp-then-label", "then"), nodeList(b.nodes, depth + 1));
      br.appendChild(then);
      card.appendChild(br);
    });
    card.append(button("+ Else if", "ghost", () => { n.branches.push({ match: "all", rules: [{ field: "os.id", op: "eq", value: "" }], nodes: [] }); rerender(); }));
    const els = el("div", "bp-branch bp-else");
    els.append(el("div", "bp-branch-head"));
    els.firstChild.append(el("span", "bp-cond", "Else"));
    n.else = n.else || [];
    els.appendChild(nodeList(n.else, depth + 1));
    card.appendChild(els);
    return card;
  }

  function render() {
    root.replaceChildren(el("div", "bp-start", "Device is assigned to this blueprint"), nodeList(tree, 0));
  }

  root.hidden = false;
  render();
  // the JSON stays editable: re-render the visual map when it changes by hand
  field.addEventListener("change", () => {
    try { const t = JSON.parse(field.value); if (Array.isArray(t)) { tree = t; render(); } } catch (e) { /* server validates */ }
  });
})();
