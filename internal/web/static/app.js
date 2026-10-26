// Pide confirmación antes de enviar los formularios que la requieren. Debe
// registrarse ANTES que el manejador de "ejecutando", para que al cancelar no
// se bloqueen los botones.
document.querySelectorAll("form[data-confirm]").forEach(function (form) {
  form.addEventListener("submit", function (e) {
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
      e.stopImmediatePropagation();
    }
  });
});

// Muestra "ejecutando" y bloquea los botones mientras corre una operación larga
// (apt puede tardar minutos). Se espera un tick para no perder el valor del botón pulsado.
document.querySelectorAll("form.js-busy").forEach(function (form) {
  form.addEventListener("submit", function () {
    var busy = form.querySelector(".busy");
    if (busy) busy.hidden = false;
    setTimeout(function () {
      form.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
    }, 0);
  });
});
