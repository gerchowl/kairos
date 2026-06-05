/* Participants table — Tabulator-backed: inline editing, selection,
   filtering, add-row with name autofill. Data + endpoints come from the
   #part-data JSON payload rendered by poll.html. */
/* global Tabulator */
(function () {
  var el = document.getElementById("part-table");
  var dataEl = document.getElementById("part-data");
  if (!el || !dataEl || typeof Tabulator === "undefined") return;
  var cfg = JSON.parse(dataEl.textContent);

  function post(url, fields) {
    var form = document.createElement("form");
    form.method = "post";
    form.action = url;
    fields.csrf = cfg.csrf;
    Object.keys(fields).forEach(function (k) {
      var inp = document.createElement("input");
      inp.type = "hidden";
      inp.name = k;
      inp.value = fields[k];
      form.appendChild(inp);
    });
    document.body.appendChild(form);
    form.submit();
  }

  var stateBadge = { pending: "badge-warning", stale: "badge-info", current: "badge-success" };

  var columns = [
    { formatter: "rowSelection", titleFormatter: "rowSelection", hozAlign: "center",
      headerSort: false, width: 36, cssClass: "part-col-select" },
    { title: "Name", field: "name", editor: cfg.open ? "input" : false, widthGrow: 2,
      formatter: function (cell) { return cell.getValue() || '<span class="opacity-40">—</span>'; } },
    { title: "Email", field: "email", editor: cfg.open ? "input" : false, widthGrow: 3,
      validator: ["required", "regex:^[^@\\s]+@[^@\\s]+\\.[^@\\s]{2,}$"] },
    { title: "Optional", field: "optional", hozAlign: "center", width: 100,
      headerTooltip: "Invitees are required by default — tick to make optional. \"via link\" rows responded on the share link without an invite.",
      formatter: function (cell) {
        var d = cell.getRow().getData();
        if (d.kind !== "invite") return '<span class="badge badge-ghost badge-sm" title="Responded via the share link — not invited">via link</span>';
        return '<input type="checkbox" class="checkbox checkbox-xs align-middle"' +
               (cell.getValue() ? " checked" : "") + (cfg.open ? "" : " disabled") + ">";
      },
      cellClick: function (e, cell) {
        var d = cell.getRow().getData();
        if (!cfg.open || d.kind !== "invite") return;
        cell.setValue(!cell.getValue());
      } },
    { title: "State", field: "state", hozAlign: "center", width: 100,
      formatter: function (cell) {
        var v = cell.getValue();
        return '<span class="badge badge-sm ' + (stateBadge[v] || "badge-ghost") + '">' + v + "</span>";
      } },
    { title: "Last contacted", field: "last_contact", headerSort: true, widthGrow: 2,
      formatter: function (cell) {
        var d = cell.getRow().getData();
        var label = cell.getValue() || "never";
        var extra = d.contacts_n > 1 ? ' <span class="opacity-50">(+' + (d.contacts_n - 1) + ")</span>" : "";
        return '<span class="text-xs opacity-70" title="' + (d.trail || "") + '">' + label + extra + "</span>";
      } },
    { formatter: function () { return '<span class="part-del-x" title="Remove">✕</span>'; },
      hozAlign: "center", width: 44, headerSort: false,
      cellClick: function (e, cell) {
        if (!cfg.open) return;
        var d = cell.getRow().getData();
        if (confirm("Remove " + d.email + " from this poll?"))
          post(cfg.remove_url, { kind: d.kind, ref: d.ref });
      } },
  ];

  var footer = null;
  if (cfg.open) {
    footer = document.createElement("div");
    footer.id = "part-add-row";
    footer.innerHTML =
      '<span class="part-add-plus">+</span>' +
      '<input type="text" id="part-add-name" placeholder="name — auto-filled from email" class="input input-sm input-ghost grow">' +
      '<input type="email" id="part-add-email" placeholder="name@domain.tld" class="input input-sm input-ghost grow">' +
      '<label class="flex items-center gap-1 text-sm opacity-70"><input type="checkbox" id="part-add-optional" class="checkbox checkbox-xs"> optional</label>' +
      '<button type="button" id="part-add-btn" class="btn btn-primary btn-xs" disabled>Add</button>';
  }

  var table = new Tabulator(el, {
    data: cfg.rows,
    columns: columns,
    layout: "fitColumns",
    selectableRows: cfg.open ? true : false,
    placeholder: "No participants yet — add someone in the row below or share the link.",
    footerElement: footer,
  });

  table.on("cellEdited", function (cell) {
    var d = cell.getRow().getData();
    post(cfg.update_url, { kind: d.kind, ref: d.ref, name: d.name || "",
                           email: d.email, optional: d.optional ? "on" : "" });
  });

  // -- state filter chips ----------------------------------------------------
  document.querySelectorAll("#part-filters [data-pfilter]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll("#part-filters .btn-active").forEach(function (b) {
        b.classList.remove("btn-active");
      });
      this.classList.add("btn-active");
      var f = this.dataset.pfilter;
      if (f) table.setFilter("state", "=", f); else table.clearFilter();
      table.deselectRow();
      refreshSend();
    });
  });

  // -- email-selected --------------------------------------------------------
  var send = document.getElementById("part-send");
  function refreshSend() {
    if (!send) return;
    var n = table.getSelectedData().length;
    send.disabled = !n;
    send.textContent = "Email selected (" + n + ")";
  }
  table.on("rowSelectionChanged", refreshSend);
  if (send) send.addEventListener("click", function () {
    var emails = table.getSelectedData().map(function (d) { return d.email; });
    if (!emails.length) return;
    if (!confirm("Email " + emails.length + " selected participant(s) now? (bypasses the daily cooldown)")) return;
    var form = document.getElementById("part-form");
    emails.forEach(function (em) {
      var inp = document.createElement("input");
      inp.type = "hidden";
      inp.name = "emails";
      inp.value = em;
      form.appendChild(inp);
    });
    form.submit();
  });

  // -- footer add-row: autofill name from email patterns ---------------------
  var EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/;
  var GENERIC = ["info", "admin", "office", "mail", "contact", "noreply", "no-reply", "hello", "support", "team"];
  function guessName(email) {
    var local = (email.split("@")[0] || "").toLowerCase();
    if (!local || GENERIC.indexOf(local) !== -1) return "";
    var parts = local.split(/[._-]+/).filter(function (p) { return /^[a-z]{2,}$/.test(p); });
    if (!parts.length) return "";
    return parts.map(function (p) { return p[0].toUpperCase() + p.slice(1); }).join(" ");
  }
  table.on("tableBuilt", function () {
    var addEmail = document.getElementById("part-add-email");
    var addName = document.getElementById("part-add-name");
    var addBtn = document.getElementById("part-add-btn");
    if (!addEmail || !addBtn) return;
    var touched = false;
    function refresh() { addBtn.disabled = !EMAIL_RE.test(addEmail.value.trim()); }
    addName.addEventListener("input", function () { touched = this.value !== ""; });
    addEmail.addEventListener("input", function () {
      if (!touched) addName.value = guessName(this.value);
      refresh();
    });
    function submit() {
      if (addBtn.disabled) return;
      post(cfg.invite_url, {
        email: addEmail.value.trim(), name: addName.value.trim(),
        optional: document.getElementById("part-add-optional").checked ? "on" : "",
      });
    }
    addBtn.addEventListener("click", submit);
    [addEmail, addName].forEach(function (inp) {
      inp.addEventListener("keydown", function (e) { if (e.key === "Enter") submit(); });
    });
  });
})();
