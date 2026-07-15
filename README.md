# Media Shield — a Burp Suite extension

**Capture everything, render nothing.** Media Shield replaces images, video and audio with
bright-orange placeholders in every view a tester looks at, so an assessment of media-heavy or
adult content can be carried out **tastefully** — without explicit material ever being *displayed*
— while the underlying bytes, headers and metadata remain available for writing findings.

Built for legitimate, authorised engagements (bug bounty / VDP / commercial pentest).

---

## ⚠️ Read this first — data handling & forensics

Media Shield changes what is **rendered**. By default it does **not** change what is **stored**.
That distinction matters legally and forensically:

- **The material is still downloaded.** Burp fetches every asset over the wire. In the default
  configuration the **original bytes are retained in Proxy history and written to the Burp project
  file on disk** (`.burp` project / state file). They are *not rendered*, but they are *present*.
- **Technically "downloaded", not "viewed".** A defensible position is that the tester never
  *viewed* the material — the plugin blinded every render surface — but the bytes exist on disk and
  in memory and **could be rendered by any other tool**, or by Burp itself **if the project file is
  reopened without this extension loaded**.
- **Opening the saved project without the plugin re-exposes everything.** The shield is a live,
  in-process transform. Load the `.burp` file on a machine that doesn't have Media Shield installed
  and the native Render tab / embedded browser will display the originals normally.
- **The native "Render" tab on the *original* response is not sealable.** Media Shield cannot delete
  Burp's built-in Render tab. On a *retained* original an analyst who deliberately clicks Render
  will see the real image. Use the provided **"Media Shield 🛡" metadata tab** instead (it is
  text-only and never draws a pixel).

### If the material could be illegal (e.g. CSAM risk on an adult platform)

Do **not** rely on the default retention behaviour. Enable **No-Retention Mode** (see below), which
scrubs the original from history so the raw asset never lands in the project file — only text
metadata (hashes, dimensions, EXIF) is kept, in memory. Even then:

- Treat the engagement host, disk and project file as sensitive; use full-disk encryption.
- Follow your firm's evidence-handling / unlawful-content escalation policy. A **hash** of suspect
  material (Media Shield records SHA-256/MD5 without retaining the bytes) is usually the correct
  artifact to escalate — not the material itself.
- Get the retention posture agreed **in writing** with the client before testing.

**This tool is a safety and dignity aid. It is not a legal control and does not sanitise disk,
memory, swap, OS thumbnail caches, or anything outside Burp's own render surfaces.**

---

## What it covers

Two layers give complete coverage of "all media, all delivery methods":

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

**Layer 2 — inline body rewrite** (`text/html`, `text/css`, `image/svg+xml`) handles the only media
that never becomes its own response: `data:` URIs, inline SVG, and `poster` frames.

### Where it blinds (every human-facing render surface)

- **Burp's embedded browser / any browser proxied through Burp** — blinded in-flight (Proxy path).
- **Message-editor Render tab** in Proxy history, Repeater, Logger.
- Provides a text-only **"Media Shield 🛡"** editor tab as the safe place to inspect.

### Where it deliberately does **not** touch bytes

- **Scanner / DAST, Intruder, Extensions** — left pristine so automated analysis sees real bytes
  (media-parsing bugs, SSRF-via-image-fetch, upload polyglots, payload reflection).
- **Proxy history "original" response** — retained by default (see retention warning above).

---

## Configuration (the "Media Shield" suite tab)

| Toggle | Default | Effect |
|---|---|---|
| Shield ENABLED | on | master switch |
| Blind the browser (Proxy path) | on | swap client-facing copy; original kept in history |
| Blind Repeater / Logger render | on | belt-and-braces; those tools' stored copy is the placeholder |
| Neutralise inline `data:` / inline SVG | on | Layer 2 rewriting |
| Harvest metadata | on | extract EXIF/GPS/dimensions/hashes into the table |
| **No-Retention Mode** | **off** | also scrub originals from history — raw bytes never persist to disk |
| Excluded hosts | empty | hosts left entirely untouched (e.g. noisy analytics pixels) |

The tab also shows live counters and a **table of harvested media** (URL, declared vs. sniffed type,
size, dimensions, GPS, SHA-256) — your finding-writing surface, no pixels involved.

---

## Install

1. Build (or grab the release jar) → `build/libs/burp-media-shield-1.0.0.jar`.
2. Burp → **Extensions → Installed → Add** → Extension type **Java** → select the jar.
3. Confirm the **Media Shield** tab appears and the output log shows the load banner.
4. Set your retention posture on the tab **before** you start browsing.

## Build

**With Gradle** (canonical; bundles + relocates dependencies via the Shadow plugin):

```bash
gradle build          # -> build/libs/burp-media-shield-1.0.0.jar
```

**Without Gradle** (no install needed; plain `javac` + `jar`):

```bash
./build.sh            # downloads deps to ./.deps, compiles, assembles the fat jar
```

Match the `montoya-api` version in `build.gradle` to (or below) your Burp release if needed. The
Montoya API is provided by Burp at runtime; `metadata-extractor` + `xmpcore` are bundled into the
jar.

## Limitations

- WebSocket-delivered media and WebRTC streams are out of scope (not classic HTTP responses).
- HTML rewriting (Layer 2) is regex-based and best-effort; it is a supplement to the Layer-1 swap,
  which is the primary defence and is not regex-dependent.
- `<canvas>` pixels drawn by JavaScript from already-blinded sources are inherently blank/orange;
  canvas drawn from bytes obtained by non-media requests is not intercepted.
- Does not sanitise disk, swap, memory dumps, or OS-level thumbnail caches. See retention warning.

## Licence

MIT — see [LICENSE](LICENSE).
