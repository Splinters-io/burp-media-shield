# Media Shield — a Burp Suite extension

**Capture everything, render nothing.** Media Shield replaces images, video and audio with
bright-orange placeholders in every view a tester looks at, so an assessment of media-heavy or
adult content can be carried out **tastefully** — without explicit material ever being *displayed*
— while the underlying bytes, headers and metadata remain available for writing findings.

---

## Read this first — data handling & forensics

Media Shield changes what is **rendered**. By default it does **not** change what is **stored**.
That distinction matters legally and forensically:

- **The material is still downloaded.** Burp fetches every asset over the wire. In the default
  configuration the **original bytes are retained in Proxy history and written to the Burp project
  file on disk** (`.burp` project / state file). They are *not rendered*, but they are *present*.
- **Technically "downloaded", not "viewed" — and that is an argument, not a defence.** The plugin
  blinds every render surface, but the bytes exist on disk and in memory and **could be rendered by
  any other tool**, or by Burp itself **if the project file is reopened without this extension
  loaded**. In some jurisdictions downloading is itself the offence (in the UK, downloading an
  indecent image of a child counts as "making" it). Not legal advice — get some.
- **Opening the saved project without the plugin re-exposes everything.** The shield is a live,
  in-process transform. Load the `.burp` file on a machine that doesn't have Media Shield installed
  and the native Render tab / embedded browser will display the originals normally.
- **The native "Render" tab on the *original* response is deliberately left working.** It is the
  escape hatch for captchas — a captcha is an image, and an orange block can't be solved. On a
  *retained* original, clicking Render shows **the real content**, and Render has no idea what it
  is showing you. That is only safe when the captcha is obviously named and you understand the
  site's architecture. A captcha served from `/img/a8f3e1.jpg` looks like everything else on the
  platform. **If in doubt, stay away from the Render tab.** Map the site first, and use the
  **"Media Shield" metadata tab** (text-only, never draws a pixel) to work out what a request is
  before you look at it. If you can't say for certain it's a captcha, it isn't one.

### If the material could be illegal (e.g. CSAM risk on an adult platform) - don't do any vigilante bullshit. also the data is still written to the computer requesting it, forensically, it's there, all this offers you a safe way to navigate structures with the best efforts to suppress any media hitting your eyes/mind/heart.

Do not rely on the default retention behaviour. Enable **No-Retention Mode** (see below), which
scrubs the original from history so the raw asset never lands in the project file — only text
metadata (hashes, dimensions, EXIF) is kept, in memory. That also leaves the Render tab nothing to
show.

**No-Retention Mode is peace of mind, not forensic safety.** If it reached Burp, it crossed a
network and landed on your box: it was in memory, it passed through your network stack, and a
capture anywhere along the path has it. Scrubbing Proxy history afterwards changes none of that,
and it is not evidence the material was never on your machine. What it does is stop you stumbling
over it again later, in your own project file, weeks into writing the report. It's about not having
to unsee things.

If you think you've hit something illegal: **stop**. Don't open it, don't save it, don't go digging.
Record the URL and hash and escalate. Also:

- Treat the engagement host, disk and project file as sensitive; use full-disk encryption.
- Follow your firm's evidence-handling / unlawful-content escalation policy. A **hash** of suspect
  material (Media Shield records SHA-256/MD5 without retaining the bytes) is usually the correct
  artifact to escalate — not the material itself.
- Get the retention posture agreed **in writing** with the client before testing.

This tool is a safety and dignity aid. It is not a legal control and does not sanitise disk,
memory, swap, OS thumbnail caches, or anything outside Burp's own render surfaces.

---

## What it covers

Three layers give complete coverage of "all media, all delivery methods":

**Layer 1 — Content-Type + magic-byte swap (the backbone).**
Any response whose body is media — detected from the `Content-Type` header **and** independently
from magic bytes, so type-confusion in either direction is caught — has its body replaced with an
orange SVG placeholder that stretches to fill the element box (layout preserved). Because *remote
loads, CDN assets, CSS `background-image`s, `<img>`/`<video>`/`<audio>` sources and HLS/DASH
segments all arrive as their own HTTP responses*, this one rule blinds the overwhelming majority of
media regardless of how the page references it.

| Delivery method | Covered by | Notes |
|---|---|---|
| Remote `<img>` / `<video>` / `<audio>` (URL) | Layer 1 | fetched as its own response |
| CSS `background-image: url(...)` (remote) | Layer 1 | image fetched separately |
| Different-domain CDN / media host | Layer 1 | keyed off content, not host |
| HLS `.m3u8` / DASH `.mpd` / `.ts` segments | Layer 1 | manifests + segments both classed as video |
| `<img>` served with a wrong/spoofed type | Layer 1 | magic-byte sniff catches it |
| Inline `data:` base64 URIs (img/video/audio) | Layer 2 | rewritten in HTML/CSS bodies |
| Inline `<svg>` vector art / embedded raster | Layer 2 | SVG body overlaid; `<image href>` blanked |
| `<video poster="...">` still frame | Layer 2 | poster swapped |
| SVG served as `image/svg+xml` | Layer 2 | overlaid with orange cover |
| Media in a WebSocket **binary** frame | Layer 3 (WS) | swapped for a format-matched orange raster |
| Base64 media in a WebSocket **text**/JSON frame | Layer 3 (WS) | decoded, magic-checked, replaced |

**Layer 2 — inline body rewrite** (`text/html`, `text/css`, `image/svg+xml`) handles the only media
that never becomes its own response: `data:` URIs, inline SVG, and `poster` frames.

**Layer 3 — WebSocket frames.** WS carries no Content-Type, so the page's own JavaScript decides how
to decode a frame. The shield therefore substitutes a **real image in the same format** (an orange
JPEG for a JPEG frame, orange PNG for a PNG frame) so the app renders orange rather than a broken
image. Binary frames are format-matched; text/JSON frames are scanned for `data:` URIs and for raw
base64 that *decodes to* image magic bytes (so tokens/IDs are never touched). Only server→client
frames are altered; the same received/to-be-sent split keeps originals in WebSockets history (and
No-Retention Mode scrubs those too).

### Where it blinds (every human-facing render surface)

- Burp's embedded browser / any browser proxied through Burp — blinded in-flight (Proxy path).
- Message-editor Render tab in Proxy history, Repeater, Logger.
- Provides a text-only "Media Shield" editor tab as the safe place to inspect.

### Where it deliberately does not touch bytes

- Scanner / DAST, Intruder, Extensions — left pristine so automated analysis sees real bytes
  (media-parsing bugs, SSRF-via-image-fetch, upload polyglots, payload reflection).
- Proxy history "original" response — retained by default (see retention warning above).

---

## Configuration (the "Media Shield" suite tab)

| Toggle | Default | Effect |
|---|---|---|
| Shield ENABLED | on | master switch |
| Blind the browser (Proxy path) | on | swap client-facing copy; original kept in history |
| Blind Repeater / Logger render | on | belt-and-braces; those tools' stored copy is the placeholder |
| Neutralise inline `data:` / inline SVG | on | Layer 2 rewriting |
| Blind media in WebSocket frames | on | server→client; binary (format-matched) + base64-in-JSON |
| Harvest metadata | on | extract EXIF/GPS/dimensions/hashes into the table |
| **No-Retention Mode** | **off** | also scrub originals from history — raw bytes never reach the project file (peace of mind, not forensic safety — see above) |
| Excluded hosts | empty | hosts left entirely untouched (e.g. noisy analytics pixels) |

The tab also shows live counters and a **table of harvested media** (URL, declared vs. sniffed type,
size, dimensions, GPS, SHA-256) — your finding-writing surface, no pixels involved. **Export CSV…**
writes the full capture (incl. MD5, type-mismatch flag, notable tags and the raw EXIF/XMP dump) to
a file for reporting/evidence. The exporter is RFC-4180 quoted and neutralises CSV/formula injection
(target-controlled URLs and EXIF can't execute when the file is opened in a spreadsheet).

---

## Install

1. Grab the prebuilt jar — committed at [`dist/burp-media-shield-1.1.0.jar`](dist/burp-media-shield-1.1.0.jar)
   or attached to the [latest release](../../releases/latest) — or build it yourself (see below).
2. Burp → **Extensions → Installed → Add** → Extension type **Java** → select the jar.
3. Confirm the **Media Shield** tab appears and the output log shows the load banner.
4. Set your retention posture on the tab **before** you start browsing.

## Build

**With Gradle** (canonical; bundles + relocates dependencies via the Shadow plugin):

```bash
gradle build          # -> build/libs/burp-media-shield-1.1.0.jar
```

**Without Gradle** (no install needed; plain `javac` + `jar`):

```bash
./build.sh            # downloads deps to ./.deps, compiles, assembles the fat jar
```

Match the `montoya-api` version in `build.gradle` to (or below) your Burp release if needed. The
Montoya API is provided by Burp at runtime; `metadata-extractor` + `xmpcore` are bundled into the
jar.

## Tests

```bash
tests/run.sh
```

Two harnesses, no Gradle/JUnit required:

- **`tests/LogicTests.java`** — detection (incl. type-confusion), placeholder generation, `data:`/
  base64 rewriting, CSV export (quoting + injection safety), and metadata extraction.
- **`tests/RealWebSocketTest.java`** — stands up a **real RFC-6455 WebSocket server**, connects with
  the JDK's real `java.net.http.WebSocket` client, pushes a real JPEG (binary frame) and a JSON
  frame carrying a base64 PNG, runs each through the shipped `WsMediaRewriter` exactly as
  `MediaWebSocketHandler` does, then **decodes the output and asserts the pixels are orange** — proof
  that real media over a real WebSocket comes out blinded, with metadata harvested. (Burp's own
  `ProxyMessageHandler` dispatch is thin glue over this and is verified by loading the jar in Burp.)

### In-Burp live check

Open [`examples/ws-selftest.html`](examples/ws-selftest.html) in Burp's browser (extension loaded).
It sends a locally-drawn test image to a WebSocket echo server and renders the echo (server→client)
back. **Shield ON → the "Received" pane is an orange placeholder; Shield OFF → it's the original
image.** Three buttons exercise the binary-frame, `data:`-URI-in-JSON, and raw-base64-in-JSON paths.
This is the one check that exercises Burp's actual proxy dispatch end-to-end in the live browser.

## Limitations

- WebSocket media **is** blinded (binary frames + base64-in-JSON, server→client). Remaining WS
  caveats: media split across continuation frames is only partially neutralised (the leading
  fragment); MSE/streamed video segments break rather than show orange; and app-specific binary
  wrappers around media may evade magic-byte detection. WebRTC media (SRTP — not carried over the
  WebSocket proxy) remains out of scope.
- HTML rewriting (Layer 2) is regex-based and best-effort; it is a supplement to the Layer-1 swap,
  which is the primary defence and is not regex-dependent.
- `<canvas>` pixels drawn by JavaScript from already-blinded sources are inherently blank/orange;
  canvas drawn from bytes obtained by non-media requests is not intercepted.
- Does not sanitise disk, swap, memory dumps, or OS-level thumbnail caches. See retention warning.

## Licence

MIT — see [LICENSE](LICENSE).
