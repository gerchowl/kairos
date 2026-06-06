/* Participants table — Tabulator-backed: inline editing, selection,
   filtering, add-row with name autofill. Data + endpoints come from the
   #part-data JSON payload rendered by poll.html. */
/* global Tabulator */
(function () {
  var el = document.getElementById("part-table");
  var dataEl = document.getElementById("part-data");
  if (!el || !dataEl || typeof Tabulator === "undefined") return;
  var cfg = JSON.parse(dataEl.textContent);

  // fetch-based posts: no page navigation, so scroll and focus survive
  function post(url, fields, then) {
    var body = new URLSearchParams(fields);
    body.set("csrf", cfg.csrf);
    fetch(url, { method: "POST", body: body, redirect: "follow" }).then(function (r) {
      if (!r.ok) return r.json().then(function (j) {
        alert(j.detail || "Action failed");
      }).catch(function () { alert("Action failed"); });
      if (then) then();
    });
  }

  function toast(msg, ok) {
    var t = document.createElement("div");
    t.className = "toast toast-end z-50";
    // role=status so screen readers announce it; errors stay until dismissed
    t.innerHTML = '<div role="status" class="alert ' + (ok ? "alert-success" : "alert-error") +
                  ' shadow-lg"><span></span>' +
                  (ok ? "" : '<button type="button" class="btn btn-ghost btn-xs">\u2715</button>') +
                  "</div>";
    t.querySelector("span").textContent = msg;
    var x = t.querySelector("button");
    if (x) x.addEventListener("click", function () { t.remove(); });
    document.body.appendChild(t);
    if (ok) setTimeout(function () { t.remove(); }, 4000);
  }

  function freshSentinel() {
    return { kind: "new", ref: "", email: "", name: "", optional: false,
             state: "", last_contact: "", contacts_n: 0, trail: "", via_link: false };
  }

  // re-read the server-rendered payload and swap the table data in place
  function refreshRows(focusAdd) {
    fetch(location.pathname).then(function (r) { return r.text(); }).then(function (html) {
      var doc = new DOMParser().parseFromString(html, "text/html");
      var data = JSON.parse(doc.getElementById("part-data").textContent);
      var rows = data.rows;
      if (cfg.open) rows.push(freshSentinel());
      table.replaceData(rows).then(function () {
        if (!focusAdd) return;
        setTimeout(function () {  // let Tabulator finish rendering first
          var sentinel = table.getRows().find(function (r2) { return r2.getData().kind === "new"; });
          if (sentinel) sentinel.getCell("email").edit();
        }, 50);
      });
    });
  }

  var stateBadge = { pending: "badge-warning", stale: "badge-info", current: "badge-success" };
  var stateLabel = { pending: "no reply", stale: "outdated", current: "up to date" };
  var stateTip = { pending: "Has not responded yet",
                   stale: "Responded before the newest dates were added",
                   current: "Response covers all current dates" };

  var columns = [
    { formatter: "rowSelection", titleFormatter: "rowSelection", hozAlign: "center",
      headerHozAlign: "center", headerSort: false, width: 40, cssClass: "part-col-select" },
    { title: "Email", field: "email", editor: cfg.open ? "input" : false, widthGrow: 3,
      formatter: function (cell) {
        var d = cell.getRow().getData();
        if (d.kind === "new" && !cell.getValue())
          return '<span class="opacity-40">+ add by email\u2026</span>';
        return cell.getValue() || "";
      } },
    { title: "Name", field: "name", editor: cfg.open ? "input" : false, widthGrow: 2,
      formatter: function (cell) {
        var d = cell.getRow().getData();
        if (d.kind === "new")
          return cell.getValue() || '<span class="opacity-30">auto-filled from email</span>';
        return cell.getValue() || '<span class="opacity-40">\u2014</span>';
      } },
    { title: "Optional", field: "optional", hozAlign: "center", width: 100,
      headerTooltip: "Everyone counts as required for finding a date — tick to make someone optional.",
      formatter: function (cell) {
        return '<input type="checkbox" class="checkbox checkbox-xs align-middle"' +
               (cell.getValue() ? " checked" : "") + (cfg.open ? "" : " disabled") + ">";
      },
      cellClick: function (e, cell) {
        if (!cfg.open) return;
        cell.setValue(!cell.getValue());
      } },
    { title: "Invited", field: "joined", width: 130,
      headerTooltip: "\u2709 invited by mail on this date \u00b7 \ud83d\udd17 self-joined via the share link (date of their first response)",
      formatter: function (cell) {
        var d = cell.getRow().getData();
        if (d.kind === "new" || !cell.getValue()) return "";
        return '<span class="text-xs opacity-70" title="' +
               (d.via_link ? "Self-joined via the share link" : "Invited by mail") +
               '">' + cell.getValue() + "</span>";
      } },
    { title: "State", field: "state", hozAlign: "center", width: 110,
      headerTooltip: "no reply = hasn't responded · outdated = responded before the newest dates · up to date = covers all current dates",
      formatter: function (cell) {
        var v = cell.getValue();
        if (!v) return "";
        return '<span class="badge badge-sm ' + (stateBadge[v] || "badge-ghost") + '" title="' +
               (stateTip[v] || "") + '">' + (stateLabel[v] || v) + "</span>";
      } },
    { title: "Last contacted", field: "last_contact", headerSort: true, widthGrow: 2,
      formatter: function (cell) {
        var d = cell.getRow().getData();
        if (d.kind === "new") return "";
        var label = cell.getValue() || "never";
        var extra = d.contacts_n > 1 ? ' <span class="opacity-50">(+' + (d.contacts_n - 1) + ")</span>" : "";
        return '<span class="text-xs opacity-70" title="' + (d.trail || "") + '">' + label + extra + "</span>";
      } },
    { formatter: function (cell) {
        return cell.getRow().getData().kind === "new"
          ? "" : '<span class="part-del-x" title="Remove">\u2715</span>';
      },
      hozAlign: "center", width: 44, headerSort: false,
      cellClick: function (e, cell) {
        if (!cfg.open) return;
        var d = cell.getRow().getData();
        if (d.kind === "new") return;
        if (confirm("Remove " + d.email + " from this poll?"))
          post(cfg.remove_url, { kind: d.kind, ref: d.ref }, refreshRows);
      } },
  ];

  if (cfg.open) cfg.rows.push(freshSentinel());

  var table = new Tabulator(el, {
    data: cfg.rows,
    columns: columns,
    layout: "fitColumns",
    selectableRows: cfg.open ? true : false,
    selectableRowsCheck: function (row) { return row.getData().kind !== "new"; },
    placeholder: "No participants yet — share the link.",
    rowFormatter: function (row) {
      row.getElement().classList.toggle("part-new-row", row.getData().kind === "new");
    },
  });

  function newRowLast() {
    var rows = table.getRows("active");
    if (!rows.length) return;
    var sentinel = rows.find(function (r) { return r.getData().kind === "new"; });
    if (sentinel && rows[rows.length - 1] !== sentinel)
      table.moveRow(sentinel, rows[rows.length - 1], false);
  }
  table.on("dataSorted", function () { setTimeout(newRowLast, 0); });

  table.on("cellEdited", function (cell) {
    var d = cell.getRow().getData();
    if (d.kind === "new") {
      // Notion-style: the bottom row IS the add form — a valid email commits
      if (cell.getField() === "email" && EMAIL_RE.test((d.email || "").trim()))
        post(cfg.invite_url, { email: d.email.trim(),
                               name: (d.name || guessName(d.email)).trim(),
                               optional: d.optional ? "on" : "" },
             function () { refreshRows(true); });  // stay put, reopen the add row
      return;  // name/optional edits just wait for the email
    }
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
      if (f) table.setFilter(function (data) { return data.kind === "new" || data.state === f; });
      else table.clearFilter();
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
    var body = new URLSearchParams();
    body.set("csrf", cfg.csrf);
    emails.forEach(function (em) { body.append("emails", em); });
    fetch(cfg.remind_selected_url, { method: "POST", body: body, redirect: "follow" })
      .then(function (r) {
        // CONTRACT: the route 302s to a path-only URL with the counts as
        // query params; after redirect:"follow", r.url is the resolved
        // absolute URL — if that redirect shape changes, update this parse.
        var q = new URL(r.url).searchParams;
        var n = (parseInt(q.get("inv") || 0, 10) || 0) + (parseInt(q.get("upd") || 0, 10) || 0);
        toast(r.ok ? (n ? "Sent " + n + " email" + (n === 1 ? "" : "s") + "."
                        : "Nothing to send.") : "Sending failed.", r.ok);
        table.deselectRow();
        refreshRows();
      })
      .catch(function () { toast("Network error — nothing was sent.", false); });
  });

  // smart reminders: same inline treatment — no page jump
  var smart = document.getElementById("part-smart");
  if (smart) smart.addEventListener("click", function () {
    var body = new URLSearchParams();
    body.set("csrf", cfg.csrf);
    fetch(cfg.remind_url, { method: "POST", body: body, redirect: "follow" })
      .then(function (r) {
        var q = new URL(r.url).searchParams;
        var n = (parseInt(q.get("inv") || 0, 10) || 0) + (parseInt(q.get("upd") || 0, 10) || 0);
        toast(r.ok ? (n ? "Sent " + n + " reminder" + (n === 1 ? "" : "s") + "."
                        : "Everyone is up to date — nothing sent.") : "Sending failed.", r.ok);
        refreshRows();
      })
      .catch(function () { toast("Network error — nothing was sent.", false); });
  });

  // -- name guessing for the add row (first.last@ -> First Last) --------------
  var EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/;
  var GENERIC = ["info", "admin", "office", "mail", "contact", "noreply", "no-reply", "hello", "support", "team"];
  function guessName(email) {
    var local = (email.split("@")[0] || "").toLowerCase();
    if (!local || GENERIC.indexOf(local) !== -1) return "";
    var parts = local.split(/[._-]+/).filter(function (p) { return /^[a-z]{2,}$/.test(p); });
    if (!parts.length) return "";
    return parts.map(function (p) { return p[0].toUpperCase() + p.slice(1); }).join(" ");
  }
})();
