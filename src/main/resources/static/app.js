// Small progressive enhancements for every page. Everything works without it, just with fewer comforts.
// Loaded as a file because the CSP forbids inline scripts.
'use strict';
(function () {
  // Confirmation before destructive actions: <form data-confirm="Delete this site?">
  document.addEventListener('submit', function (event) {
    const form = event.target;
    if (form.dataset && form.dataset.confirm && !window.confirm(form.dataset.confirm)) event.preventDefault();
  });

  // Copy buttons: <button data-copy="id-of-element">
  document.querySelectorAll('[data-copy]').forEach(function (button) {
    button.addEventListener('click', function () {
      const source = document.getElementById(button.dataset.copy);
      if (!source || !navigator.clipboard) return;
      navigator.clipboard.writeText(source.textContent).then(function () {
        const label = button.textContent;
        button.textContent = 'Copied';
        setTimeout(function () { button.textContent = label; }, 1500);
      });
    });
  });

  // Command templates filled from inputs: <pre id="x" data-template="... {domain} ... {port}"> and
  // <input data-fills="x" data-key="domain" data-allowed="a-z0-9.,-">. Characters outside data-allowed are dropped,
  // so a field can never add a second shell argument.
  document.querySelectorAll('input[data-fills]').forEach(function (input) {
    input.addEventListener('input', function () {
      const target = document.getElementById(input.dataset.fills);
      if (!target || !target.dataset.template) return;
      let text = target.dataset.template;
      document.querySelectorAll('input[data-fills="' + input.dataset.fills + '"]').forEach(function (field) {
        const allowed = new RegExp('[^' + (field.dataset.allowed || 'a-z0-9') + ']', 'g');
        const value = field.value.toLowerCase().replace(allowed, '') || field.placeholder;
        text = text.split('{' + field.dataset.key + '}').join(value);
      });
      target.textContent = text;
    });
  });

  // Selects that submit their form on change: <select data-autosubmit>
  document.querySelectorAll('select[data-autosubmit]').forEach(function (select) {
    select.addEventListener('change', function () { if (select.form) select.form.requestSubmit(); });
  });
})();
