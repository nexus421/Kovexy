// Kovexy captcha page script, served at /.kovexy/captcha.js. Runs the invisible reCAPTCHA v3 (the checkbox of v2 is sent by
// the button of the form, it needs no script of ours).
'use strict';
(function () {
  var form = document.getElementById('kovexy-captcha');
  if (!form) return;

  if (form.dataset.provider === 'recaptcha3') {
    var key = form.dataset.sitekey;
    var wait = function () {
      if (!window.grecaptcha || !window.grecaptcha.ready) return setTimeout(wait, 100);
      window.grecaptcha.ready(function () {
        window.grecaptcha.execute(key, { action: 'kovexy' }).then(function (token) {
          form.querySelector('input[name=g-recaptcha-response]').value = token;
          form.submit();
        });
      });
    };
    wait();
  }
})();
