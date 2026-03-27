# Civil Engineering Suite

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](https://civilengsuite.is-a.dev/)
[![Status](https://img.shields.io/badge/Status-Live-brightgreen.svg)](https://civilengsuite.is-a.dev/)
[![ACI](https://img.shields.io/badge/Standard-ACI%20318--19-blue.svg)](https://civilengsuite.is-a.dev/footing-pro/)
[![Offline](https://img.shields.io/badge/Mode-100%25%20Offline-gold.svg)](https://civilengsuite.is-a.dev/footing-pro/)

**🌐 [civilengsuite.is-a.dev](https://civilengsuite.is-a.dev/?utm_source=github&utm_medium=readme&utm_campaign=organic)**

Professional-grade structural and civil engineering software by **Eng. Aymn Asi** — Structural Engineer.

> *Built by engineers, for engineers. Free. Offline. No installation.*

---

## 🏗️ Applications

### [Footing Pro v.2026](https://civilengsuite.is-a.dev/footing-pro/?utm_source=github&utm_medium=readme&utm_campaign=organic) — Combined Footing Design Software ● **Live Now**

The most advanced combined footing design application available for free.

| Feature | Detail |
|---|---|
| **Modules** | 17 engineering calculation modules |
| **Standard** | ACI 318-19 compliant |
| **Mode** | 100% offline — no internet required after download |
| **Platform** | Microsoft Excel on Windows |
| **File** | Single-file application — no installation |
| **Price** | Free (personal license required) |
| **Language** | English + Arabic (عربي) |

**Modules include:** Soil pressure distribution · Column load transfer · Shear force diagrams · Bending moment diagrams · One-way shear check · Punching shear check · Flexural reinforcement design · Development length · Footing geometry validation · Load combinations · Boundary constraint checks · RC dimension enforcement · Multi-form live sync · Dual-mode engine · Intelligent validation · Intelligent print system · Personal lock system

### In Development — Coming 2026

| App | Description |
|---|---|
| [Beam Pro](https://civilengsuite.is-a.dev/beam-pro/) | ACI 318 RC beam design — shallow beam bending |
| [Column Pro](https://civilengsuite.is-a.dev/column-pro/) | RC column design — P-M interaction, biaxial bending, slenderness, punching shear (17 sub-modules) |
| [Deflection Pro](https://civilengsuite.is-a.dev/deflection-pro/) | ACI 318 deflection checks for RC beams & slabs |
| [Earthquake Pro](https://civilengsuite.is-a.dev/earthquake-pro/) | Seismic design — base shear, lateral load distribution, structural period |
| [Mur Pro](https://civilengsuite.is-a.dev/mur-pro/) | Ultimate Resistance Moment (Mur) — Egyptian Code (ECP) |
| [Add Reft Pro](https://civilengsuite.is-a.dev/add-reft-pro/) | Additional reinforcement for flat slab openings |
| [Section Property Pro](https://civilengsuite.is-a.dev/section-property-pro/) | Cross-section properties — area, centroid, Ix/Iy, section modulus, radius of gyration |

---

## 📁 Repository Structure

```
/
├── index.html              ← [GITIGNORED] Civil Engineering Suite source (encrypted → pc_suite.enc)
├── footing-pro/
│   └── index.html          ← [GITIGNORED] Footing Pro v.2026 source (encrypted → footing_pro.enc)
├── beam-pro/
│   └── index.html          ← Beam Pro marketing/preview page (static)
├── column-pro/
│   └── index.html          ← Column Pro marketing/preview page (static)
├── deflection-pro/
│   └── index.html          ← Deflection Pro marketing/preview page (static)
├── earthquake-pro/
│   └── index.html          ← Earthquake Pro marketing/preview page (static)
├── mur-pro/
│   └── index.html          ← Mur Pro marketing/preview page (static)
├── add-reft-pro/
│   └── index.html          ← Add Reft Pro marketing/preview page (static)
├── section-property-pro/
│   └── index.html          ← Section Property Pro marketing/preview page (static)
├── public/
│   ├── pc_suite.enc        ← AES-256-GCM encrypted main page
│   └── footing_pro.enc     ← AES-256-GCM encrypted Footing Pro page
├── api/
│   ├── decrypt.js          ← Serverless: AES-256-GCM decrypt → serve HTML
│   ├── csp-report.js       ← Serverless: CSP violation report receiver
│   └── getenc.js           ← Disabled (raw .enc exposure removed)
├── images/
│   ├── favicon.ico
│   ├── apple-touch-icon.png
│   └── activation-infographic.png
├── sitemap.xml             ← XML sitemap with image entries + hreflang (9 pages)
├── robots.txt              ← Crawler rules (allows search engines, blocks AI scrapers)
├── 404.html                ← Custom 404 error page
├── 404.css                 ← Styles for 404 page (external file — strict CSP compatible)
├── vercel.json             ← Vercel deployment config (headers, rewrites, redirects)
├── CNAME                   ← civilengsuite.is-a.dev
├── .nojekyll               ← Disables Jekyll on GitHub Pages
├── .gitattributes          ← LF line ending normalization
├── .gitignore              ← Protects raw HTML source and encryption keys
└── README.md               ← This file
```

> ⚠️ The raw `index.html` source files are **never committed**. Only the AES-256-GCM encrypted `.enc` files are in the repository. The encryption key lives in `CES_DECRYPT_KEY` (Vercel environment variable) and is never stored in git.

---

## 🚀 Vercel Deployment

1. Import this repository in [vercel.com](https://vercel.com)
2. Set environment variables:
   - `CES_DECRYPT_KEY` — 32-byte AES key as 64-character hex string
   - `CES_XOR_KEY` *(optional)* — single-byte XOR obfuscation key as 2-character hex
   - `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` *(optional)* — distributed rate limiting
3. Custom domain: `civilengsuite.is-a.dev`
4. Enable **Enforce HTTPS**

---

## 🔑 Keywords

`combined footing design` · `foundation design software` · `ACI 318` · `structural engineering software` · `free civil engineering tools` · `footing calculator` · `reinforced concrete design` · `offline engineering software` · `Excel structural design` · `تصميم القواعد` · `برنامج تصميم الأساسات`

---

## ⚖️ License & Copyright

© 2026 **Civil Engineering Suite** — **Eng. Aymn Asi** — All Rights Reserved.

This repository hosts the **product landing pages only**. The Footing Pro v.2026 application itself is proprietary software protected by a device-locked licensing system. Unauthorized copying, redistribution, or reverse engineering is strictly prohibited.

For licensing inquiries, visit: [civilengsuite.is-a.dev/#contact](https://civilengsuite.is-a.dev/#contact)

---

*Made with ❤️ by Eng. Aymn Asi — Structural Engineer*
