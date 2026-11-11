/* New-poll date picker: infinite-scroll calendar with rectangular drag
 * selection, week/weekday toggles, and year/month navigation. */
(function () {
    'use strict';

    var body = document.getElementById('cal-body');
    if (!body) return;

    var sel = new Set();
    var INITIAL_WEEKS = 20;
    var MAX_YEARS_AHEAD = 5;
    var LOAD_MORE_WEEKS = 13;
    var MO = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    var today = new Date(); today.setHours(0, 0, 0, 0);
    var cells = {};
    var totalWeeks = 0;
    var dragging = false, dragStart = null, dragCur = null, dragAdd = true;

    function fmt(d) {
        return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    }
    function monthKey(d) {
        return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
    }
    function getMon(d) {
        var dt = new Date(d), dy = dt.getDay(); dt.setDate(dt.getDate() + ((dy === 0 ? -6 : 1) - dy)); return dt;
    }
    function wkNum(d) {
        var t = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
        var n = t.getUTCDay() || 7; t.setUTCDate(t.getUTCDate() + 4 - n);
        var y = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
        return Math.ceil((((t - y) / 864e5) + 1) / 7);
    }

    var start = getMon(today);
    var limit = new Date(today); limit.setFullYear(limit.getFullYear() + MAX_YEARS_AHEAD);
    var monthRows = {};

    function lastShown() {
        var d = new Date(start); d.setDate(d.getDate() + totalWeeks * 7 - 1); return d;
    }

    function addWeeks(count) {
        var startW = totalWeeks;
        for (var w = startW; w < startW + count; w++) {
            var tr = document.createElement('tr');
            var wkD = new Date(start); wkD.setDate(wkD.getDate() + w * 7);
            var wkTd = document.createElement('td');
            wkTd.className = 'cal-wk-cell';
            wkTd.textContent = 'W' + wkNum(wkD);
            wkTd.dataset.row = w;
            wkTd.addEventListener('click', function () { toggleRow(parseInt(this.dataset.row, 10)); });
            tr.appendChild(wkTd);

            for (var d = 0; d < 7; d++) {
                var cur = new Date(start); cur.setDate(cur.getDate() + w * 7 + d);
                var key = fmt(cur), isPast = cur < today || cur > limit;  // past the horizon reads as unselectable too
                var td = document.createElement('td');
                if (d >= 5) td.classList.add('cal-we-col');
                if (cur.getMonth() % 2 === 1) td.classList.add('month-alt');

                var div = document.createElement('div');
                div.className = 'cal-cell';
                if (isPast) div.classList.add('past');
                if (fmt(cur) === fmt(today)) div.classList.add('today');
                div.textContent = cur.getDate();
                div.dataset.date = key; div.dataset.row = w; div.dataset.col = d;

                var mk = monthKey(cur);
                if (cur.getDate() === 1) {
                    var band = document.createElement('span');
                    band.className = 'month-band';
                    band.textContent = MO[cur.getMonth()];
                    div.appendChild(band);
                }
                // The calendar opens on the current week, so the current month's
                // 1st is usually never rendered: its first visible row stands in.
                if ((cur.getDate() === 1 || (w === 0 && d === 0)) && !monthRows[mk]) monthRows[mk] = tr;
                // A week holding a month's 1st belongs to that month (it is the row
                // a month button jumps to); any other week to its Thursday's month.
                // The first row is today's week: it belongs to today's month even
                // when it also holds the next month's 1st (e.g. Dec 28 - Jan 3).
                if (w === 0) tr.dataset.month = monthKey(today);
                else if (cur.getDate() === 1) tr.dataset.month = mk;
                else if (d === 3 && !tr.dataset.month) tr.dataset.month = mk;

                div.addEventListener('mousedown', onDown);
                div.addEventListener('mouseenter', onEnter);
                td.appendChild(div); tr.appendChild(td);
                cells[w + ',' + d] = { date: key, el: div, past: isPast };
            }
            body.insertBefore(tr, sentinel);
        }
        totalWeeks = startW + count;
    }

    // Create sentinel row for infinite scroll
    var sentinel = document.createElement('tr');
    sentinel.id = 'cal-sentinel';
    var sentinelTd = document.createElement('td');
    sentinelTd.colSpan = 8;
    sentinelTd.style.cssText = 'height:1px;border:none;padding:0;';
    sentinel.appendChild(sentinelTd);
    body.appendChild(sentinel);

    // Load initial weeks
    addWeeks(INITIAL_WEEKS);

    // IntersectionObserver for lazy loading
    var scrollContainer = document.getElementById('cal-scroll');
    var observer = new IntersectionObserver(function (entries) {
        if (entries[0].isIntersecting && lastShown() < limit) addWeeks(LOAD_MORE_WEEKS);
    }, { root: scrollContainer, rootMargin: '200px' });
    observer.observe(sentinel);

    // Year + Month navigation
    var yearSelect = document.getElementById('cal-year');
    var monthBtns = document.getElementById('cal-month-btns').querySelectorAll('button');

    function updateNav() {
        // Built once: every year up to the horizon, not only the loaded ones (a
        // jump loads its weeks on demand). Rebuilding on each lazy load would
        // close a dropdown the user has open.
        var curYears = [];
        for (var y = today.getFullYear(); y <= limit.getFullYear(); y++) curYears.push(y);
        yearSelect.innerHTML = '';
        curYears.forEach(function (y) {
            var opt = document.createElement('option');
            opt.value = y; opt.textContent = y;
            yearSelect.appendChild(opt);
        });
        // Keep current selection if still valid
        if (yearSelect._selectedYear && curYears.indexOf(yearSelect._selectedYear) !== -1) {
            yearSelect.value = yearSelect._selectedYear;
        } else {
            yearSelect.value = curYears[0];
            yearSelect._selectedYear = curYears[0];
        }
        updateMonthBtns();
    }

    function updateMonthBtns() {
        var yr = parseInt(yearSelect.value, 10);
        var nowY = today.getFullYear(), nowM = today.getMonth();
        for (var i = 0; i < 12; i++) {
            var btn = monthBtns[i];
            // Only disable months in the past
            if (yr < nowY || (yr === nowY && i < nowM) || new Date(yr, i, 1) > limit) {
                btn.disabled = true;
                btn.classList.add('cal-month-disabled');
            } else {
                btn.disabled = false;
                btn.classList.remove('cal-month-disabled');
            }
        }
    }

    function loadUntilMonth(targetMk) {
        // Weeks are appended until the target month's 1st is on screen. The
        // bound is in calendar time, not attempts: a month never reachable from
        // here can not grow the table by decades of rows.
        var parts = targetMk.split('-');
        var target = new Date(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, 1);
        if (target > limit) return;
        while (!monthRows[targetMk] && lastShown() < target) addWeeks(LOAD_MORE_WEEKS);
    }

    // A freshly loaded month's row is among the last rows, and the box cannot
    // scroll a row to its top with nothing below it: load a box-height more.
    function ensureRowsBelow(tr) {
        var rowH = tr.getBoundingClientRect().height || 36;
        var need = Math.ceil(scrollContainer.clientHeight / rowH) + 1;
        while (totalWeeks - 1 - tr.sectionRowIndex < need && lastShown() < limit) addWeeks(LOAD_MORE_WEEKS);
    }

    // Scroll only the calendar box. scrollIntoView would also scroll the page,
    // which is what made the whole form jump on every month click.
    function scrollToRow(tr) {
        var head = document.getElementById('cal-grid').querySelector('thead');
        var top = tr.getBoundingClientRect().top - scrollContainer.getBoundingClientRect().top
            - scrollContainer.clientTop + scrollContainer.scrollTop - head.offsetHeight;
        top = Math.max(0, top);
        // Smooth over a few screens; instant across years, where a smooth scroll
        // would crawl through hundreds of rows for seconds.
        var far = Math.abs(top - scrollContainer.scrollTop) > 3 * scrollContainer.clientHeight;
        scrollContainer.scrollTo({ top: top, behavior: far ? 'auto' : 'smooth' });
    }

    function jumpTo(mk) {
        if (!monthRows[mk]) loadUntilMonth(mk);
        var tr = monthRows[mk];
        if (!tr) return;
        ensureRowsBelow(tr);
        // The destination is known, so show it right away and keep showing it
        // until the user scrolls by hand: rows passing by during the smooth
        // scroll, or a row shared by two months, must not rewrite the year.
        pinned = mk; showMonth(mk);
        scrollToRow(tr);
    }

    yearSelect.addEventListener('change', function () {
        var yr = parseInt(this.value, 10);
        yearSelect._selectedYear = yr;
        updateMonthBtns();
        var m = yr === today.getFullYear() ? today.getMonth() : 0;
        jumpTo(yr + '-' + String(m + 1).padStart(2, '0'));
    });

    for (var mi = 0; mi < monthBtns.length; mi++) {
        (function (idx) {
            monthBtns[idx].addEventListener('click', function () {
                if (this.disabled) return;
                var yr = parseInt(yearSelect.value, 10);
                jumpTo(yr + '-' + String(idx + 1).padStart(2, '0'));
            });
        })(mi);
    }

    updateNav();

    var activeMk = null, pinned = null;
    ['wheel', 'touchstart', 'keydown', 'mousedown'].forEach(function (ev) {
        scrollContainer.addEventListener(ev, function () { pinned = null; }, { passive: true });
    });
    function markActiveMonth() {
        if (pinned) { showMonth(pinned); return; }
        var boxTop = scrollContainer.getBoundingClientRect().top
            + document.getElementById('cal-grid').querySelector('thead').offsetHeight;
        var rows = body.rows, top = null;
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].dataset.month && rows[i].getBoundingClientRect().bottom > boxTop + 1) { top = rows[i]; break; }
        }
        if (top) showMonth(top.dataset.month);
    }
    function showMonth(mk) {
        if (mk === activeMk) return;
        activeMk = mk;
        var yr = parseInt(mk.slice(0, 4), 10);
        if (yr !== parseInt(yearSelect.value, 10)) {
            yearSelect.value = yr; yearSelect._selectedYear = yr; updateMonthBtns();
        }
        monthBtns.forEach(function (b, i) {
            var on = i === parseInt(mk.slice(5), 10) - 1;
            b.classList.toggle('cal-month-active', on);
            if (on) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
        });
    }
    var activeQueued = false;
    scrollContainer.addEventListener('scroll', function () {
        if (activeQueued) return;
        activeQueued = true;
        requestAnimationFrame(function () { activeQueued = false; markActiveMonth(); });
    }, { passive: true });
    markActiveMonth();

    // Rectangular drag
    function getRect() {
        if (!dragStart || !dragCur) return [];
        var r1 = Math.min(dragStart.r, dragCur.r), r2 = Math.max(dragStart.r, dragCur.r);
        var c1 = Math.min(dragStart.c, dragCur.c), c2 = Math.max(dragStart.c, dragCur.c);
        var out = [];
        for (var r = r1; r <= r2; r++) {
            for (var c = c1; c <= c2; c++) {
                var cell = cells[r + ',' + c]; if (cell && !cell.past) out.push(cell);
            }
        }
        return out;
    }
    function onDown(e) {
        e.preventDefault();
        if (this.classList.contains('past')) return;
        dragging = true;
        dragStart = { r: parseInt(this.dataset.row, 10), c: parseInt(this.dataset.col, 10) };
        dragCur = { r: dragStart.r, c: dragStart.c };
        dragAdd = !sel.has(this.dataset.date);
        updatePreview();
    }
    function onEnter() {
        if (!dragging) return;
        dragCur = { r: parseInt(this.dataset.row, 10), c: parseInt(this.dataset.col, 10) };
        updatePreview();
    }
    document.addEventListener('mouseup', function () {
        if (!dragging) return;
        getRect().forEach(function (c) { if (dragAdd) sel.add(c.date); else sel.delete(c.date); });
        dragging = false; dragStart = null; dragCur = null;
        clearPreview(); updateUI();
    });
    function updatePreview() {
        clearPreview();
        getRect().forEach(function (c) { c.el.classList.add(dragAdd ? 'drag-add' : 'drag-remove'); });
    }
    function clearPreview() {
        document.querySelectorAll('.drag-add,.drag-remove').forEach(function (el) {
            el.classList.remove('drag-add', 'drag-remove');
        });
    }

    function toggleRow(r) {
        var rc = []; for (var c = 0; c < 7; c++) { var cell = cells[r + ',' + c]; if (cell && !cell.past) rc.push(cell); }
        var all = rc.every(function (c) { return sel.has(c.date); });
        rc.forEach(function (c) { if (all) sel.delete(c.date); else sel.add(c.date); }); updateUI();
    }
    document.getElementById('cal-grid').querySelector('thead').addEventListener('click', function (e) {
        var th = e.target.closest('th'); if (!th || th.classList.contains('cal-wk')) return;
        var ci = Array.from(th.parentElement.children).indexOf(th) - 1; if (ci < 0) return;
        var cc = []; for (var r = 0; r < totalWeeks; r++) { var cell = cells[r + ',' + ci]; if (cell && !cell.past) cc.push(cell); }
        var all = cc.every(function (c) { return sel.has(c.date); });
        cc.forEach(function (c) { if (all) sel.delete(c.date); else sel.add(c.date); }); updateUI();
    });

    function updateUI() {
        Object.values(cells).forEach(function (c) { c.el.classList.toggle('selected', sel.has(c.date)); });
        var sorted = Array.from(sel).sort();
        var el = document.getElementById('selected-summary');
        el.textContent = sorted.length ? sorted.length + ' date' + (sorted.length > 1 ? 's' : '') + ' selected' : 'No dates selected';
        if (clearBtn) clearBtn.hidden = sorted.length === 0;
        var hid = document.getElementById('hidden-dates'); hid.innerHTML = '';
        sorted.forEach(function (d) {
            var inp = document.createElement('input'); inp.type = 'hidden'; inp.name = 'dates'; inp.value = d; hid.appendChild(inp);
        });
    }

    var clearBtn = document.getElementById('cal-clear');
    if (clearBtn) clearBtn.addEventListener('click', function () { sel.clear(); updateUI(); });

    // time-fields toggle + validation only exist on the create page; the edit
    // page reuses this picker with a fixed mode and optional date additions.
    var modeSel = document.getElementById('mode-select');
    var timeFields = document.getElementById('time-fields');
    if (modeSel && timeFields) {
        modeSel.addEventListener('change', function () {
            timeFields.classList.toggle('hidden', this.value !== 'time_slot');
        });
    }
    var form = document.getElementById('poll-form');
    form.addEventListener('submit', function (e) {
        if (form.hasAttribute('data-require-dates') && sel.size === 0) {
            e.preventDefault(); alert('Please select at least one date.'); return;
        }
        var startEl = document.getElementById('time-start');
        var endEl = document.getElementById('time-end');
        if (modeSel && modeSel.value === 'time_slot' && startEl && endEl) {
            if (!startEl.value || !endEl.value) { e.preventDefault(); alert('Please set start and end times.'); return; }
            if (startEl.value >= endEl.value) { e.preventDefault(); alert('Start time must be before end time.'); return; }
        }
    });
    updateUI();
})();
