// Starts Swagger UI for /api/v1/openapi.json on /api/v1/docs. A file of its
// own: the CSP allows no inline script.
;(function () {
  'use strict'
  var dark = window.matchMedia('(prefers-color-scheme: dark)')
  function theme() {
    document.documentElement.classList.toggle('dark-mode', dark.matches)
  }
  theme()
  dark.addEventListener('change', theme)

  // Opened by a signed in console user, calls without an authorized token go
  // with the session cookie; state changes then need the session's CSRF token,
  // which the console reads from GET /api/v1/me as well.
  var csrf = ''
  fetch('/api/v1/me', { credentials: 'same-origin' })
    .then(function (r) {
      return r.ok ? r.json() : null
    })
    .then(function (me) {
      if (!me || !me.csrf_token) return
      csrf = me.csrf_token
      var el = document.getElementById('apidocs-session')
      el.textContent = 'Signed in as ' + me.login + ': calls without an authorized token use your console session.'
      el.hidden = false
    })
    .catch(function () {})

  window.SwaggerUIBundle({
    url: '/api/v1/openapi.json',
    dom_id: '#swagger-ui',
    deepLinking: true,
    validatorUrl: null, // the default asks validator.swagger.io
    persistAuthorization: false, // a token lives only as long as the page
    requestInterceptor: function (req) {
      if (!req.headers.Authorization && csrf && !/^(GET|HEAD|OPTIONS)$/i.test(req.method || 'GET')) {
        req.headers['X-CSRF-Token'] = csrf
      }
      return req
    },
  })
})()
