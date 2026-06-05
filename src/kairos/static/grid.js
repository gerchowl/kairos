/* Scheduler availability grids.
 *
 * Widgets auto-initialize from JSON payloads embedded by the templates:
 *   #ts-grid-data       — when2meet-style time-slot grid (heatmap + optional picking)
 *   #fullday-cal-data   — full-day response calendar (template-rendered, JS-painted)
 *   .sched-bar[data-*]  — stacked yes/maybe/no summary bars
 *
 * Payloads may carry `saved` ({slot_id: av}) — the visitor's stored response —
 * which seeds the picker and drives the Save button's dirty state (#save-btn
 * is disabled and reads "Saved" until something changes).
 *
 * Dynamic colors are painted here (not in templates) from the active theme's
 * CSS custom properties; a MutationObserver repaints on data-theme switches.
 */
(function () {
    'use strict';

    var CYCLE = ['yes', 'maybe', 'no'];
    var ICON = { yes: '✓', maybe: '?', no: '✗' };
    var themeRepaint = [];

    function cssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function readJSON(id) {
        var el = document.getElementById(id);
        return el ? JSON.parse(el.textContent) : null;
    }

    function parseHex(hex) {
        if (hex.length === 4) hex = '#' + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3];
        return [parseInt(hex.slice(1, 3), 16), parseInt(hex.slice(3, 5), 16), parseInt(hex.slice(5, 7), 16)];
    }

    /* Heatmap shade: interpolate the theme's heat base toward --color-yes.
     * Colors come from the active theme so light and dark both work. */
    function heatPainter() {
        var base = parseHex(cssVar('--sched-heat-base'));
        var yes = parseHex(cssVar('--color-yes'));
        var yesFg = cssVar('--color-yes-fg');
        return {
            bg: function (alpha) {
                var c = base.map(function (b, i) { return Math.round(b + alpha * (yes[i] - b)); });
                return 'rgb(' + c.join(',') + ')';
            },
            fg: function (alpha) { return alpha > 0.3 ? yesFg : ''; }
        };
    }

    /* Rectangular drag with yes/maybe/no cycling, shared by both pickers.
     * cfg: {slotAt: {"r,c": slotId}, paint(state, rect, previewState),
     *       hiddenId, initial?: {slotId: av}, onChange?()}
     * paint is called with rect=null after commit (repaint from state only). */
    function dragCycle(cfg) {
        var state = {};
        if (cfg.initial) {
            Object.keys(cfg.initial).forEach(function (k) { state[k] = cfg.initial[k]; });
        }
        var dragging = false, start = null, cur = null, dragState = 0;

        function rect() {
            if (!start || !cur) return null;
            return {
                r1: Math.min(start.r, cur.r), r2: Math.max(start.r, cur.r),
                c1: Math.min(start.c, cur.c), c2: Math.max(start.c, cur.c)
            };
        }
        function syncHidden() {
            var container = document.getElementById(cfg.hiddenId);
            container.innerHTML = '';
            Object.keys(cfg.slotAt).forEach(function (key) {
                var inp = document.createElement('input');
                inp.type = 'hidden';
                inp.name = 'av_' + cfg.slotAt[key];
                inp.value = state[cfg.slotAt[key]] || 'no';
                container.appendChild(inp);
            });
        }
        function onDown(e) {
            e.preventDefault();
            var r = parseInt(this.dataset.row, 10), c = parseInt(this.dataset.col, 10);
            if (!cfg.slotAt[r + ',' + c]) return;
            dragging = true;
            start = { r: r, c: c };
            cur = { r: r, c: c };
            var curState = state[cfg.slotAt[r + ',' + c]];
            dragState = (curState === undefined) ? 0 : ((CYCLE.indexOf(curState) + 1) % 3);
            cfg.paint(state, rect(), CYCLE[dragState]);
        }
        function onEnter() {
            if (!dragging) return;
            cur = { r: parseInt(this.dataset.row, 10), c: parseInt(this.dataset.col, 10) };
            cfg.paint(state, rect(), CYCLE[dragState]);
        }
        document.addEventListener('mouseup', function () {
            if (!dragging) return;
            var rc = rect();
            for (var r = rc.r1; r <= rc.r2; r++) {
                for (var c = rc.c1; c <= rc.c2; c++) {
                    var sid = cfg.slotAt[r + ',' + c];
                    if (sid) state[sid] = CYCLE[dragState];
                }
            }
            dragging = false;
            start = cur = null;
            cfg.paint(state, null, null);
            syncHidden();
            if (cfg.onChange) cfg.onChange();
        });
        syncHidden();
        cfg.paint(state, null, null);
        return {
            state: state,
            repaint: function () { cfg.paint(state, null, null); },
            attach: function (el) {
                el.addEventListener('mousedown', onDown);
                el.addEventListener('mouseenter', onEnter);
            }
        };
    }

    /* Save button dirty-tracking: disabled + "Saved" while the grid and the
     * name/email fields match the stored response; enabled on any change. */
    function bindSaveButton(drag, saved, slotIds) {
        var btn = document.getElementById('save-btn');
        var form = document.getElementById('response-form');
        if (!btn || !form) return null;
        var nameEl = form.querySelector('input[name=name]');
        var emailEl = form.querySelector('input[name=email]');
        var init = { name: nameEl ? nameEl.value : '', email: emailEl ? emailEl.value : '' };
        function norm(st) {
            return slotIds.map(function (id) { return st[id] || 'no'; }).join();
        }
        var savedNorm = saved ? norm(saved) : null;
        function update() {
            var clean = savedNorm !== null
                && norm(drag.state) === savedNorm
                && (!nameEl || nameEl.value === init.name)
                && (!emailEl || emailEl.value === init.email);
            btn.disabled = clean;
            btn.textContent = clean ? 'Saved' : 'Save Response';
        }
        if (nameEl) nameEl.addEventListener('input', update);
        if (emailEl) emailEl.addEventListener('input', update);
        update();
        return update;
    }

    /* -- Stacked summary bars (yes/maybe/no widths from data attributes) -- */
    function initSummaryBars() {
        document.querySelectorAll('.sched-bar[data-total]').forEach(function (bar) {
            var total = Math.max(parseInt(bar.dataset.total, 10) || 0, 1);
            CYCLE.forEach(function (k) {
                var n = parseInt(bar.dataset[k], 10) || 0;
                var seg = document.createElement('div');
                seg.className = 'sched-seg-' + k;
                seg.style.width = (n / total * 100).toFixed(0) + '%';
                bar.appendChild(seg);
            });
        });
    }

    /* -- Time-slot grid: dates=columns, times=rows, heatmap cells -- */
    function initTsGrid() {
        var data = readJSON('ts-grid-data');
        var table = document.getElementById('ts-grid');
        if (!data || !table) return;

        var CV = {};
        var heatRef = {};
        function readThemeColors() {
            CV.yes = cssVar('--color-badge-yes');
            CV.maybe = cssVar('--color-badge-maybe');
            CV.no = cssVar('--color-badge-no');
            heatRef.heat = heatPainter();
        }
        readThemeColors();

        var thead = table.querySelector('thead tr');
        var tbody = table.querySelector('tbody');
        var gapSet = {};
        data.gaps.forEach(function (g) { gapSet[g] = true; });
        var rowGapSet = {};
        (data.time_gaps || []).forEach(function (g) { rowGapSet[g] = true; });
        var slotAt = {};
        data.grid.forEach(function (g) { slotAt[g.row + ',' + g.col] = g.id; });
        var cellEls = {}, badgeEls = {};

        data.dates.forEach(function (d, ci) {
            var th = document.createElement('th');
            th.className = 'ts-hdr';
            var dayDiv = document.createElement('div');
            dayDiv.textContent = d.day;
            var dateDiv = document.createElement('div');
            dateDiv.className = 'ts-hdr-date';
            dateDiv.textContent = d.label;
            th.appendChild(dayDiv);
            th.appendChild(dateDiv);
            if (gapSet[ci]) th.classList.add('ts-gap-after');
            thead.appendChild(th);
        });

        data.times.forEach(function (t, ri) {
            var tr = document.createElement('tr');
            if (rowGapSet[ri]) tr.classList.add('ts-gap-below');
            var timeTd = document.createElement('td');
            timeTd.className = 'ts-time';
            timeTd.textContent = t;
            tr.appendChild(timeTd);

            for (var ci = 0; ci < data.dates.length; ci++) {
                var td = document.createElement('td');
                td.className = 'ts-cell';
                if (gapSet[ci]) td.classList.add('ts-gap-after');
                var div = document.createElement('div');
                var key = ri + ',' + ci;
                var sid = slotAt[key];
                var hm = sid ? data.heatmap[sid] : null;
                div.className = 'ts-slot';
                if (hm) {
                    div.textContent = hm.count;
                    if (hm.tip) div.title = hm.tip;
                    if (data.interactive) div.classList.add('ts-active');
                    if (data.decidable) div.dataset.decideSlot = sid;
                } else {
                    div.classList.add('ts-empty');
                }
                div.dataset.row = ri;
                div.dataset.col = ci;

                var badge = document.createElement('span');
                badge.className = 'ts-badge';
                div.appendChild(badge);

                td.appendChild(div);
                tr.appendChild(td);
                cellEls[key] = div;
                badgeEls[key] = badge;
            }
            tbody.appendChild(tr);
        });

        // Viewer-local times: when the browser tz differs from the poll's,
        // note it and add the local time to each slot's tooltip.
        var localTz = null;
        try { localTz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { /* old browser */ }
        if (localTz && data.tz && localTz !== data.tz) {
            var note = document.getElementById('ts-tz-note');
            if (note) note.textContent = 'Times shown in ' + data.tz +
                ' — hover a slot for your local time (' + localTz + ').';
            data.grid.forEach(function (g) {
                if (!g.epoch) return;
                var el = cellEls[g.row + ',' + g.col];
                var local = new Date(g.epoch * 1000).toLocaleString([], {
                    weekday: 'short', month: 'short', day: 'numeric',
                    hour: '2-digit', minute: '2-digit'
                });
                el.title = (el.title ? el.title + '\n' : '') + 'Your time: ' + local;
            });
        }

        function paintHeatCells() {
            data.grid.forEach(function (g) {
                var el = cellEls[g.row + ',' + g.col];
                var hm = data.heatmap[g.id];
                el.style.background = heatRef.heat.bg(hm.alpha);
                el.style.color = heatRef.heat.fg(hm.alpha);
            });
        }
        paintHeatCells();

        var drag = null;
        themeRepaint.push(function () {
            readThemeColors();
            paintHeatCells();
            if (drag) drag.repaint();
        });

        if (!data.interactive) return;

        function setBadge(key, st) {
            var badge = badgeEls[key];
            badge.textContent = ICON[st];
            badge.style.background = CV[st];
            badge.style.display = 'flex';
        }
        var saveUpdate = null;
        drag = dragCycle({
            slotAt: slotAt,
            hiddenId: 'sched-hidden-avails',
            initial: data.saved || null,
            onChange: function () { if (saveUpdate) saveUpdate(); },
            paint: function (state, rc, pv) {
                data.grid.forEach(function (g) {
                    var key = g.row + ',' + g.col;
                    cellEls[key].style.boxShadow = 'none';
                    if (state[g.id]) {
                        setBadge(key, state[g.id]);
                    } else {
                        badgeEls[key].textContent = '';
                        badgeEls[key].style.display = 'none';
                    }
                });
                if (!rc) return;
                for (var r = rc.r1; r <= rc.r2; r++) {
                    for (var c = rc.c1; c <= rc.c2; c++) {
                        var key = r + ',' + c;
                        if (!slotAt[key] || !cellEls[key]) continue;
                        setBadge(key, pv);
                        cellEls[key].style.boxShadow = 'inset 0 0 0 2px rgba(147,197,253,0.6)';
                    }
                }
            }
        });
        data.grid.forEach(function (g) { drag.attach(cellEls[g.row + ',' + g.col]); });
        saveUpdate = bindSaveButton(drag, data.saved || null,
            data.grid.map(function (g) { return g.id; }));
    }

    /* -- Full-day response calendar: cells rendered by the template -- */
    function initFulldayCal() {
        var data = readJSON('fullday-cal-data');
        if (!data) return;

        var BG = {}, FG = {};
        function readThemeColors() {
            CYCLE.forEach(function (k) {
                BG[k] = cssVar('--color-' + k);
                FG[k] = cssVar('--color-' + k + '-fg');
            });
        }
        readThemeColors();

        var slotAt = {};
        data.grid.forEach(function (g) { slotAt[g.row + ',' + g.col] = g.id; });
        var cellEls = {};
        document.querySelectorAll('.slot-cell').forEach(function (el) {
            cellEls[el.dataset.row + ',' + el.dataset.col] = el;
        });

        function paintCell(el, st) {
            el.style.background = BG[st];
            el.style.color = FG[st];
            el.childNodes[0].nodeValue = ICON[st];
        }
        var saveUpdate = null;
        var drag = dragCycle({
            slotAt: slotAt,
            hiddenId: 'sched-hidden-avails',
            initial: data.saved || null,
            onChange: function () { if (saveUpdate) saveUpdate(); },
            paint: function (state, rc, pv) {
                data.grid.forEach(function (g) {
                    var el = cellEls[g.row + ',' + g.col];
                    if (!el) return;
                    el.style.outline = 'none';
                    if (state[g.id]) {
                        paintCell(el, state[g.id]);
                    } else {
                        el.style.background = '';
                        el.style.color = '';
                        el.childNodes[0].nodeValue = el.dataset.day;
                    }
                });
                if (!rc) return;
                for (var r = rc.r1; r <= rc.r2; r++) {
                    for (var c = rc.c1; c <= rc.c2; c++) {
                        var el = cellEls[r + ',' + c];
                        if (!el || !slotAt[r + ',' + c]) continue;
                        paintCell(el, pv);
                        el.style.outline = '2px solid #93c5fd';
                        el.style.outlineOffset = '-2px';
                    }
                }
            }
        });
        data.grid.forEach(function (g) {
            var el = cellEls[g.row + ',' + g.col];
            if (el) drag.attach(el);
        });
        saveUpdate = bindSaveButton(drag, data.saved || null,
            data.grid.map(function (g) { return g.id; }));

        themeRepaint.push(function () {
            readThemeColors();
            drag.repaint();
        });
    }

    /* -- Decide picker: click a slot in the matrix to choose the final date.
     * Any element with data-decide-slot is clickable and two-way synced with
     * the #decide-select dropdown. -- */
    function initDecidePicker() {
        var select = document.getElementById('decide-select');
        var cells = document.querySelectorAll('[data-decide-slot]');
        if (!select || !cells.length) return;
        function mark(sid) {
            document.querySelectorAll('.decide-sel').forEach(function (el) {
                el.classList.remove('decide-sel');
            });
            var el = document.querySelector('[data-decide-slot="' + sid + '"]');
            if (el) el.classList.add('decide-sel');
        }
        cells.forEach(function (el) {
            el.classList.add('decide-clickable');
            if (!el.title) el.title = 'Click to choose as the final date';
            el.addEventListener('click', function () {
                select.value = this.dataset.decideSlot;
                mark(this.dataset.decideSlot);
            });
        });
        select.addEventListener('change', function () { mark(this.value); });
        mark(select.value);
    }

    initSummaryBars();
    initTsGrid();
    initFulldayCal();
    initDecidePicker();

    /* Repaint JS-painted colors when the navbar theme toggle flips data-theme */
    new MutationObserver(function () {
        themeRepaint.forEach(function (f) { f(); });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
})();
