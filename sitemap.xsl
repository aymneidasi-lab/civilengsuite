<?xml version="1.0" encoding="UTF-8"?>
<!--
  sitemap.xsl — Civil Engineering Suite
  Browser-side XSLT stylesheet for sitemap.xml visual display.

  PURPOSE:
  When a browser loads sitemap.xml, this stylesheet transforms the raw XML
  into a readable HTML table. Without it, Chrome renders XML as flat unstyled
  text. With it, the sitemap appears as a structured, navigable table.

  This file is served as a static asset from the repo root.
  It is listed in STATIC_PASSTHROUGH in functions/[[path]].js (v7 [V3]) so it
  bypasses route matching and is served directly by Cloudflare Pages.

  CSP NOTE: XSLT execution uses the sitemap.xml response's CSP, not this file's.
  The sitemap handler in [[path]].js returns ONLY Content-Type + Cache-Control —
  no CSP — so XSLT processing is unrestricted.

  Added: 2026-04-25 [V-XSL]
-->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:sm="http://www.sitemaps.org/schemas/sitemap/0.9"
  xmlns:image="http://www.google.com/schemas/sitemap-image/1.1"
  exclude-result-prefixes="sm image">

  <xsl:output method="html" encoding="UTF-8" indent="yes"
    doctype-system="about:legacy-compat"/>

  <xsl:template match="/">
    <html lang="en">
      <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
        <meta name="robots" content="noindex, nofollow"/>
        <title>Sitemap — Civil Engineering Suite</title>
        <style>
          *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0A1A2E;
            color: #CBD5E1;
            min-height: 100vh;
            padding: 32px 16px;
          }

          .container { max-width: 960px; margin: 0 auto; }

          header {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid #1E3A5F;
          }

          .badge {
            background: #C17B1A;
            color: #fff;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            padding: 4px 10px;
            border-radius: 4px;
          }

          h1 {
            font-size: 1.4rem;
            font-weight: 600;
            color: #E2E8F0;
          }

          .subtitle {
            font-size: 0.8rem;
            color: #64748B;
            margin-top: 2px;
          }

          .stats {
            display: flex;
            gap: 24px;
            margin-bottom: 24px;
          }

          .stat {
            background: #0F2744;
            border: 1px solid #1E3A5F;
            border-radius: 8px;
            padding: 12px 20px;
          }

          .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: #C17B1A;
          }

          .stat-label {
            font-size: 0.72rem;
            color: #64748B;
            text-transform: uppercase;
            letter-spacing: 0.06em;
          }

          table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
          }

          thead th {
            background: #0F2744;
            color: #8AA3C7;
            font-weight: 600;
            font-size: 0.72rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            padding: 10px 14px;
            text-align: left;
            border-bottom: 2px solid #1E3A5F;
          }

          tbody tr {
            border-bottom: 1px solid #0F2744;
            transition: background 0.15s;
          }

          tbody tr:hover { background: #0F2744; }

          td {
            padding: 12px 14px;
            vertical-align: top;
          }

          td.url a {
            color: #C17B1A;
            text-decoration: none;
            word-break: break-all;
          }

          td.url a:hover { text-decoration: underline; }

          td.priority .pill {
            display: inline-block;
            background: #1E3A5F;
            color: #8AA3C7;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.72rem;
            font-weight: 600;
          }

          td.priority .pill.high { background: #1C3A1A; color: #4ADE80; }
          td.priority .pill.med  { background: #2A2A1A; color: #FACC15; }

          td.changefreq { color: #64748B; font-size: 0.75rem; }
          td.lastmod    { color: #64748B; white-space: nowrap; font-size: 0.75rem; }

          .images-list { margin-top: 4px; }
          .image-entry {
            display: flex;
            align-items: flex-start;
            gap: 6px;
            margin-top: 4px;
            font-size: 0.72rem;
            color: #64748B;
          }
          .image-entry::before {
            content: "🖼";
            font-size: 0.7rem;
            margin-top: 1px;
            flex-shrink: 0;
          }
          .image-entry a { color: #5B8AC7; text-decoration: none; word-break: break-all; }
          .image-entry a:hover { text-decoration: underline; }

          footer {
            margin-top: 32px;
            padding-top: 20px;
            border-top: 1px solid #1E3A5F;
            font-size: 0.72rem;
            color: #334155;
            text-align: center;
          }

          footer a { color: #475569; text-decoration: none; }
          footer a:hover { color: #8AA3C7; }
        </style>
      </head>
      <body>
        <div class="container">
          <header>
            <div>
              <h1>Civil Engineering Suite — Sitemap</h1>
              <div class="subtitle">
                <a href="https://civilengsuite.pages.dev/" style="color:#64748B;text-decoration:none">
                  civilengsuite.pages.dev
                </a>
              </div>
            </div>
            <div class="badge">XML Sitemap</div>
          </header>

          <div class="stats">
            <div class="stat">
              <div class="stat-value">
                <xsl:value-of select="count(sm:urlset/sm:url)"/>
              </div>
              <div class="stat-label">URLs</div>
            </div>
            <div class="stat">
              <div class="stat-value">
                <xsl:value-of select="count(sm:urlset/sm:url/image:image)"/>
              </div>
              <div class="stat-label">Images</div>
            </div>
          </div>

          <table>
            <thead>
              <tr>
                <th style="width:50%">URL</th>
                <th>Last Modified</th>
                <th>Change Freq</th>
                <th>Priority</th>
              </tr>
            </thead>
            <tbody>
              <xsl:for-each select="sm:urlset/sm:url">
                <tr>
                  <td class="url">
                    <a href="{sm:loc}">
                      <xsl:value-of select="sm:loc"/>
                    </a>
                    <xsl:if test="image:image">
                      <div class="images-list">
                        <xsl:for-each select="image:image">
                          <div class="image-entry">
                            <a href="{image:loc}">
                              <xsl:value-of select="image:loc"/>
                            </a>
                          </div>
                        </xsl:for-each>
                      </div>
                    </xsl:if>
                  </td>
                  <td class="lastmod">
                    <xsl:value-of select="sm:lastmod"/>
                  </td>
                  <td class="changefreq">
                    <xsl:value-of select="sm:changefreq"/>
                  </td>
                  <td class="priority">
                    <xsl:variable name="p" select="sm:priority"/>
                    <span class="pill">
                      <xsl:choose>
                        <xsl:when test="$p >= 0.9">
                          <xsl:attribute name="class">pill high</xsl:attribute>
                        </xsl:when>
                        <xsl:when test="$p >= 0.7">
                          <xsl:attribute name="class">pill med</xsl:attribute>
                        </xsl:when>
                        <xsl:otherwise>
                          <xsl:attribute name="class">pill</xsl:attribute>
                        </xsl:otherwise>
                      </xsl:choose>
                      <xsl:value-of select="$p"/>
                    </span>
                  </td>
                </tr>
              </xsl:for-each>
            </tbody>
          </table>

          <footer>
            Sitemap for
            <a href="https://civilengsuite.pages.dev/">civilengsuite.pages.dev</a>
            &#160;·&#160;
            <a href="https://www.sitemaps.org/protocol.html">Sitemap Protocol 0.9</a>
            &#160;·&#160;
            <a href="https://search.google.com/search-console">Google Search Console</a>
          </footer>
        </div>
      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>
