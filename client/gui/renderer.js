// Renders `greendot-client --json list` and forwards button clicks back to
// the CLI. Every displayed string (dot, reason, transport, check labels) is
// opaque CLI output — the GUI holds no storage or vendor knowledge.

const $ = (sel) => document.querySelector(sel);
let busy = false;

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    node.append(c);
  }
  return node;
}

function banner(message) {
  const b = $("#banner");
  b.textContent = message || "";
  b.hidden = !message;
}

async function invoke(args) {
  const reply = await window.greendot.invoke(args);
  if (!reply.ok) throw new Error(reply.error || "unknown error");
  return reply;
}

// One privileged action at a time; refresh afterwards either way.
async function action(args) {
  if (busy) return;
  busy = true;
  document.body.style.cursor = "progress";
  try {
    await invoke(args);
    banner("");
  } catch (e) {
    banner(e.message);
  } finally {
    busy = false;
    document.body.style.cursor = "";
    refresh();
  }
}

function exportRow(target, e) {
  const isNvme = e.kind === "nvme";
  const connected = e.transport != null;
  const actions = [];
  if (e.enabled) {
    actions.push(
      el(
        "button",
        {
          class: connected ? "danger" : "primary",
          onclick: () =>
            action(
              isNvme
                ? [connected ? "disconnect" : "connect", target.name, e.name]
                : [connected ? "unmount" : "mount", target.name, e.name],
            ),
        },
        [isNvme ? (connected ? "Disconnect" : "Connect") : connected ? "Unmount" : "Mount"],
      ),
    );
  }
  actions.push(
    el("button", { onclick: () => showDiagnose(target.name, e.name) }, ["Diagnose"]),
  );
  const dotClass = e.enabled ? e.dot || "red" : "gray";
  return el("tr", {}, [
    el("td", {}, [el("span", { class: `dot ${dotClass}`, title: e.reason || "" })]),
    el("td", {}, [
      el("span", { class: "kind" }, [e.kind]),
      e.name,
      el("div", { class: "reason" }, [e.enabled ? e.reason || "" : "disabled on target"]),
    ]),
    el("td", {}, [el("span", { class: "place" }, [e.device || e.mountpoint || ""])]),
    el("td", { class: "actions" }, actions),
  ]);
}

function targetCard(t) {
  const state = t.reachable
    ? ""
    : el("div", { class: "reason" }, [`unreachable: ${t.error || ""}`]);
  const rows = (t.exports || []).map((e) => exportRow(t, e));
  return el("div", { class: "target" }, [
    el("header", {}, [
      el("h3", {}, [
        t.name,
        el("span", { class: "host" }, [t.host]),
        " ",
        el("button", { class: "danger", onclick: () => removeTarget(t.name) }, ["Remove"]),
      ]),
      state || "",
    ]),
    rows.length
      ? el("table", {}, [el("tbody", {}, rows)])
      : el("div", { class: "empty" }, [
          t.reachable ? "no exports on this target" : "",
        ]),
  ]);
}

async function removeTarget(name) {
  if (!confirm(`Forget target ${name}? (Connections and mounts stay up.)`)) return;
  await action(["remove", name]);
}

async function refresh() {
  try {
    const reply = await invoke(["list"]);
    $("#hostnqn").textContent = reply.hostnqn || "";
    const main = $("#targets");
    main.replaceChildren();
    if (!reply.targets.length) {
      main.append(
        el("div", { class: "empty" }, [
          "No targets yet — press “Add target” and paste a connection string.",
        ]),
      );
    }
    for (const t of reply.targets) {
      main.append(targetCard(t));
    }
  } catch (e) {
    banner(e.message);
  }
}

async function showDiagnose(...args) {
  const title = args.length ? `Diagnose ${args.join(" › ")}` : "Diagnose this machine";
  $("#diag-title").textContent = title;
  const list = $("#diag-checks");
  list.replaceChildren(el("li", {}, ["…"]));
  $("#diag-dialog").showModal();
  try {
    const reply = await invoke(["diagnose", ...args]);
    list.replaceChildren(
      ...reply.checks.map((c) =>
        el("li", { class: c.ok ? "ok" : "bad" }, [
          el("span", { class: "mark" }, [c.ok ? "✓" : "✗"]),
          c.label,
          c.detail ? el("div", { class: "detail" }, [c.detail]) : "",
        ]),
      ),
    );
  } catch (e) {
    list.replaceChildren(el("li", { class: "bad" }, [e.message]));
  }
}

// -- wiring --

$("#add-target").addEventListener("click", () => {
  $("#add-string").value = "";
  $("#add-name").value = "";
  $("#add-dialog").showModal();
});

$("#add-confirm").addEventListener("click", async () => {
  const string = $("#add-string").value.trim();
  if (!string) return;
  const name = $("#add-name").value.trim();
  $("#add-dialog").close();
  await action(["add", string, ...(name ? ["--name", name] : [])]);
});

$("#diagnose-local").addEventListener("click", () => showDiagnose());

document.querySelectorAll("dialog [data-close]").forEach((b) =>
  b.addEventListener("click", () => b.closest("dialog").close()),
);

refresh();
setInterval(() => {
  if (!busy && !document.querySelector("dialog[open]")) refresh();
}, 2000);
