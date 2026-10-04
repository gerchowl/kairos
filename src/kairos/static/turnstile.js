/* Cloudflare Turnstile, click-to-load facade (issue #31, obligation A1).
 *
 * The point of this file is what it does NOT do: nothing here reaches
 * challenges.cloudflare.com until the person presses "I'm human". A page view of
 * /new or /manage therefore fetches nothing from a third party, which is what keeps
 * obligation P1 (strictly-necessary cookies only, no consent banner) true without a
 * flag that could select a state where our privacy page is false. The widget script
 * is appended to <head> inside the click handler and nowhere else -- an earlier
 * version of this file created it during init() and loaded Cloudflare on every page
 * view, which is exactly the thing the facade exists to prevent.
 *
 * Progressive enhancement throughout, because every failure mode of a third-party
 * widget has to end somewhere a human can act on:
 *
 *   - no JS at all            -> <noscript> says so, and the server refuses an
 *                                absent token with a sentence explaining it.
 *   - the script fails to load -> the submit button is re-enabled and the note says
 *                                what happened. Submitting anyway produces a clear
 *                                refusal from the server, which beats a form that
 *                                cannot be submitted at all.
 *   - the widget errors/expires -> the button is held again, because Cloudflare's
 *                                tokens are single-use and expire; a stale token
 *                                would be refused server-side anyway.
 *   - the token is verified    -> the submit button comes back and the hidden field
 *                                carries the token to siteverify.
 *
 * Server-side verification is what decides (kairos.turnstile.verify); nothing here
 * is a control, only its front end.
 */
(function () {
  "use strict";

  /* Hold the form until the check answers -- but only buttons that were usable in
   * the first place, so a form that ships a disabled button stays disabled. Done
   * before the click, deliberately: the alternative is a creator who ignores the
   * button, submits, and loses the form to a refusal page. */
  function hold(form, pending) {
    var buttons = form.querySelectorAll('button[type="submit"], input[type="submit"]');
    for (var i = 0; i < buttons.length; i++) {
      var button = buttons[i];
      if (pending) {
        if (!button.disabled) {
          button.setAttribute("data-was-enabled", "1");
          button.disabled = true;
        }
      } else if (button.getAttribute("data-was-enabled")) {
        button.removeAttribute("data-was-enabled");
        button.disabled = false;
      }
    }
  }

  function wire(box) {
    if (box.getAttribute("data-turnstile-wired")) return;
    box.setAttribute("data-turnstile-wired", "1");

    var button = box.querySelector("[data-turnstile-start]");
    var mount = box.querySelector("[data-turnstile-mount]");
    var field = box.querySelector("[data-turnstile-token]");
    var note = box.querySelector(".turnstile-note");
    var form = box.closest("form");
    if (!button || !mount || !field || !form) return;

    function say(message, bad) {
      if (!note) return;
      note.textContent = message;
      // `turnstile-note` is kept on purpose: it is the handle `wire` found this
      // element by, and replacing the class list wholesale would mean the second
      // message of a session could not find its own paragraph.
      note.className = "text-sm mt-2 turnstile-note " + (bad ? "text-warning" : "opacity-70");
    }

    function release(token) {
      field.value = token || "";
      hold(form, !token);
    }

    hold(form, true);

    function giveUp(message) {
      say(message, true);
      hold(form, false);
    }

    button.addEventListener("click", function () {
      if (box.getAttribute("data-turnstile-started")) return;
      box.setAttribute("data-turnstile-started", "1");
      button.hidden = true;
      mount.hidden = false;

      var script = document.createElement("script");
      script.src = box.getAttribute("data-script");
      script.async = true;
      script.defer = true;

      script.onerror = function () {
        giveUp("The human check could not be loaded, so the button is available again — " +
               "submit anyway and Kairos will tell you what is missing.");
      };

      script.onload = function () {
        if (!window.turnstile || typeof window.turnstile.render !== "function") {
          script.onerror();
          return;
        }
        window.turnstile.render(mount, {
          sitekey: box.getAttribute("data-sitekey"),
          action: box.getAttribute("data-action"),
          callback: function (token) {
            release(token);
            say("Thanks — the check is done, submit the form.");
          },
          "expired-callback": function () {
            release("");
            say("That check has expired. Solve it again to submit.", true);
          },
          "error-callback": function () {
            release("");
            say("The human check failed to run. Try again in a moment.", true);
          }
        });
      };

      document.head.appendChild(script);
    });
  }

  function init() {
    var boxes = document.querySelectorAll("[data-turnstile]");
    for (var i = 0; i < boxes.length; i++) wire(boxes[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();