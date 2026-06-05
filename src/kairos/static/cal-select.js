/* New-poll date picker: infinite-scroll calendar with rectangular drag
 * selection, week/weekday toggles, and year/month navigation. */
(function () {
    'use strict';

    var body = document.getElementById('cal-body');
    if (!body) return;

    var sel = new Set();
    var INITIAL_WEEKS = 20;
    var LOAD_MORE_WEEKS = 13;
    var MO = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    var today = new Date(); today.setHours(0, 0, 0, 0);
    var cells = {};
    var totalWeeks = 0;
    var dragging = false, dragStart = null, dragCur = null, dragAdd = true;

    function fmt(d) {
        return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
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
    var monthRows = {};
    var loadedYears = new Set();
    var loadedMonths = new Set();

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
                var key = fmt(cur), isPast = cur < today;
                var td = document.createElement('td');
                if (d >= 5) td.classList.add('cal-we-col');
                if (cur.getMonth() % 2 === 1) td.classList.add('month-alt');

                var div = document.createElement('div');
                div.className = 'cal-cell';
                if (isPast) div.classList.add('past');
                if (fmt(cur) === fmt(today)) div.classList.add('today');
                div.textContent = cur.getDate();
                div.dataset.date = key; div.dataset.row = w; div.dataset.col = d;

                if (cur.getDate() === 1) {
                    var band = document.createElement('span');
                    band.className = 'month-band';
                    band.textContent = MO[cur.getMonth()];
                    div.appendChild(band);
                    var mk = cur.getFullYear() + '-' + String(cur.getMonth() + 1).padStart(2, '0');
                    if (!monthRows[mk]) monthRows[mk] = tr;
                }

                div.addEventListener('mousedown', onDown);
                div.addEventListener('mouseenter', onEnter);
                td.appendChild(div); tr.appendChild(td);
                cells[w + ',' + d] = { date: key, el: div, past: isPast };

                loadedYears.add(cur.getFullYear());
                loadedMonths.add(cur.getFullYear() + '-' + String(cur.getMonth() + 1).padStart(2, '0'));
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
        if (entries[0].isIntersecting) {
            addWeeks(LOAD_MORE_WEEKS);
            updateNav();
        }
    }, { root: scrollContainer, rootMargin: '200px' });
    observer.observe(sentinel);

    // Year + Month navigation
    var yearSelect = document.getElementById('cal-year');
    var monthBtns = document.getElementById('cal-month-btns').querySelectorAll('button');

    function updateNav() {
        // Update year dropdown
        var curYears = Array.from(loadedYears).sort();
        yearSelect.innerHTML = '';
        curYears.forEach(function (y) {
            var opt = document.createElement('option');
            opt.value = y; opt.textContent = y;
            yearSelect.appendChild(opt);
        });
        // Keep current selection if still valid
        if (yearSelect._selectedYear && loadedYears.has(yearSelect._selectedYear)) {
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
            if (yr < nowY || (yr === nowY && i < nowM)) {
                btn.disabled = true;
                btn.classList.add('cal-month-disabled');
            } else {
                btn.disabled = false;
                btn.classList.remove('cal-month-disabled');
            }
        }
    }

    function loadUntilMonth(targetMk) {
        var maxAttempts = 200;
        while (!monthRows[targetMk] && maxAttempts-- > 0) {
            addWeeks(LOAD_MORE_WEEKS);
        }
        updateNav();
    }

    yearSelect.addEventListener('change', function () {
        yearSelect._selectedYear = parseInt(this.value, 10);
        updateMonthBtns();
    });

    for (var mi = 0; mi < monthBtns.length; mi++) {
        (function (idx) {
            monthBtns[idx].addEventListener('click', function () {
                if (this.disabled) return;
                var yr = parseInt(yearSelect.value, 10);
                var mk = yr + '-' + String(idx + 1).padStart(2, '0');
                if (!monthRows[mk]) loadUntilMonth(mk);
                if (monthRows[mk]) {
                    monthRows[mk].scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        })(mi);
    }

    updateNav();

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
        var hid = document.getElementById('hidden-dates'); hid.innerHTML = '';
        sorted.forEach(function (d) {
            var inp = document.createElement('input'); inp.type = 'hidden'; inp.name = 'dates'; inp.value = d; hid.appendChild(inp);
        });
    }

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
