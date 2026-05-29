# Civil Engineering Suite

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](https://civilengsuite.pages.dev/)
[![Status](https://img.shields.io/badge/Status-Live-brightgreen.svg)](https://civilengsuite.pages.dev/)
[![ECP](https://img.shields.io/badge/Standard-ECP%20203%20%2B%20ACI%20318-blue.svg)](https://civilengsuite.pages.dev/footing-pro/)
[![Offline](https://img.shields.io/badge/Mode-Offline--first-gold.svg)](https://civilengsuite.pages.dev/footing-pro/)

**🌐 [civilengsuite.pages.dev](https://civilengsuite.pages.dev/?utm_source=github&utm_medium=readme&utm_campaign=organic)**

Professional-grade structural and civil engineering software by **Eng. Aymn Asi** — Structural Engineer.

> *Built by engineers, for engineers. Offline-first. Lightweight install.*

---

## 🏗️ Applications

### [Footing Pro v.2026](https://civilengsuite.pages.dev/footing-pro/?utm_source=github&utm_medium=readme&utm_campaign=organic) — Combined Footing Design Software ● **Live Now**

Professional combined footing design — three standalone applications under one series.

| Feature | Detail |
|---|---|
| **Applications** | 3 standalone apps: Rectangular · Trapezoidal · Strap Combined Footing |
| **Modules** | 19 engineering calculation modules per app |
| **Primary Standard** | ECP 203 (Egyptian Code of Practice) |
| **Compatible With** | ACI 318 framework |
| **Mode** | Offline-first — internet required only at session start for license check |
| **Platform** | Windows 7 SP1 → Windows 11 (requires Microsoft Excel) |
| **Install** | Lightweight installer — shortcuts + uninstaller only; no registry bloat |
| **Price** | 249 EGP/year (launch price) — annual subscription, 1–10 years |
| **Language** | English + Arabic (عربي) |

**Modules include:** Soil pressure distribution · Column load transfer · Shear force diagrams · Bending moment diagrams · One-way shear check (both directions) · Punching shear check · Flexural reinforcement design · Development length · Footing geometry validation · Load combinations · Boundary constraint checks · RC dimension enforcement · Multi-form live sync · Dual-mode engine · Intelligent Stress Correction Engine · Intelligent validation · Compound shear force diagram · Longitudinal reinforcement schedule · Personal lock system

**World-first capabilities:**
1. **Intelligent Stress Correction Engine** — auto-detects negative net soil pressure, alerts engineer; engineer presses Stress Correction button, engine redistributes and propagates across all downstream outputs
2. **Circular Reference Weight Solver** — resolves weight-dimension circular dependency without manual iteration
3. **Allow/Prevent Edit Mode** — third field state: locked against input but still formula-updated by engine
4. **Tooltips on Disabled Fields** — full tooltip info stays active on locked/disabled fields

#### Segment Landing Pages
| Audience | URL |
|---|---|
| Independent Engineers | [/footing-pro/engineers/](https://civilengsuite.pages.dev/footing-pro/engineers/) |
| Engineering Offices | [/footing-pro/offices/](https://civilengsuite.pages.dev/footing-pro/offices/) |
| Students & Lecturers | [/footing-pro/students/](https://civilengsuite.pages.dev/footing-pro/students/) |

---

### In Development — Coming 2026

| App | Description |
|---|---|
| [Beam Pro](https://civilengsuite.pages.dev/beam-pro/) | RC beam design — shallow beam bending |
| [Column Pro](https://civilengsuite.pages.dev/column-pro/) | RC column design — P-M interaction, biaxial bending, slenderness, punching shear |
| [Deflection Pro](https://civilengsuite.pages.dev/deflection-pro/) | ACI 318 deflection checks for RC beams & slabs |
| [Earthquake Pro](https://civilengsuite.pages.dev/earthquake-pro/) | Seismic design — base shear, lateral load distribution, structural period |
| [Mur Pro](https://civilengsuite.pages.dev/mur-pro/) | Ultimate Resistance Moment (Mur) — Egyptian Code (ECP) |
| [Add Reft Pro](https://civilengsuite.pages.dev/add-reft-pro/) | Additional reinforcement for flat slab openings |
| [Section Property Pro](https://civilengsuite.pages.dev/section-property-pro/) | Cross-section properties — area, centroid, Ix/Iy, section modulus, radius of gyration |

---

## 📁 Repository Structure

```
/
├── index.html                    ← [GITIGNORED] PC Suite source (encrypted → pc_suite.enc)
├── footing-pro/
│   ├── index.html                ← [GITIGNORED] Footing Pro v.2026 source (encrypted → footing_pro.enc)
│   ├── engineers/
│   │   └── index.html            ← Independent engineers landing page (static)
│   ├── offices/
│   │   └── index.html            ← Engineering offices landing page (static)
│   └── students/
│       └── index.html            ← Students & lecturers landing page (static)
├── beam-pro/
│   └── index.html                ← Beam Pro marketing/preview page (static)
├── column-pro/
│   └── index.html                ← Column Pro marketing/preview page (static)
├── deflection-pro/
│   └── index.html                ← Deflection Pro marketing/preview page (static)
├── earthquake-pro/
│   └── index.html                ← Earthquake Pro marketing/preview page (static)
├── mur-pro/
│   └── index.html                ← Mur Pro marketing/preview page (static)
├── add-reft-pro/
│   └── index.html                ← Add Reft Pro marketing/preview page (static)
├── section-property-pro/
│   └── index.html                ← Section Property Pro marketing/preview page (static)
├── public/
│   ├── pc_suite.enc              ← AES-256-GCM encrypted main page
│   └── footing_pro.enc           ← AES-256-GCM encrypted Footing Pro page
├── api/
│   ├── decrypt.js                ← Serverless: AES-256-GCM decrypt → serve HTML
│   ├── csp-report.js             ← Serverless: CSP violation report receiver
│   └── getenc.js                 ← Disabled (raw .enc exposure removed)
├── images/
│   ├── favicon.ico
│   ├── apple-touch-icon.png
│   └── activation-infographic.png
├── sitemap.xml                   ← XML sitemap (12 pages: 9 apps + 3 landing pages)
├── robots.txt                    ← Crawler rules (allows search engines, blocks AI scrapers)
├── 404.html                      ← Custom 404 error page
├── 404.css                       ← Styles for 404 page (CSP-compatible external file)
├── vercel.json                   ← Vercel deployment config (headers, rewrites, redirects)
├── CNAME                         ← civilengsuite.pages.dev
├── .nojekyll                     ← Disables Jekyll on GitHub Pages
├── .gitattributes                ← LF line ending normalization
├── .gitignore                    ← Protects raw HTML source and encryption keys
└── README.md                     ← This file
```

> ⚠️ The raw `index.html` source files are **never committed**. Only the AES-256-GCM encrypted `.enc` files are in the repository. The encryption key lives in `CES_DECRYPT_KEY` (Vercel environment variable) and is never stored in git.

> ℹ️ The segment landing pages (`/engineers/`, `/offices/`, `/students/`) are static HTML — no encryption, committed directly to the repo.

---

## 🚀 Vercel Deployment

1. Import this repository in [vercel.com](https://vercel.com)
2. Set environment variables:
   - `CES_DECRYPT_KEY` — 32-byte AES key as 64-character hex string
   - `CES_XOR_KEY` *(optional)* — single-byte XOR obfuscation key as 2-character hex
   - `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` *(optional)* — distributed rate limiting
3. Custom domain: `civilengsuite.pages.dev`
4. Enable **Enforce HTTPS**

---

## 🔑 Keywords

`combined footing design` · `foundation design software` · `ECP 203` · `ACI 318` · `structural engineering software` · `footing calculator` · `reinforced concrete design` · `offline engineering software` · `تصميم القواعد المشتركة` · `برنامج تصميم الأساسات` · `الكود المصري للإنشاءات` · `برنامج مهندس إنشائي`

---

## ⚖️ License & Copyright

© 2026 **Civil Engineering Suite** — **Eng. Aymn Asi** — All Rights Reserved.

This repository hosts the **product landing pages only**. The Footing Pro v.2026 application itself is proprietary software protected by a device-locked annual subscription licensing system. Unauthorized copying, redistribution, or reverse engineering is strictly prohibited.

For licensing inquiries, visit: [civilengsuite.pages.dev/#contact](https://civilengsuite.pages.dev/#contact)

---

*Made with ❤️ by Eng. Aymn Asi — Structural Engineer*
