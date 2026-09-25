//! Erzeugt aus dem Report eine übersichtliche, in sich geschlossene HTML-Seite.
//!
//! Alle Werte stammen teils aus nicht vertrauenswürdigen Daten (Treffer aus dem
//! Image) und werden daher HTML-escaped, bevor sie in die Seite geschrieben
//! werden.

use crate::report::Report;

/// Rendert den Report als vollständige HTML-Seite.
pub fn render(report: &Report) -> String {
    let mut h = String::new();
    h.push_str("<!doctype html>\n<html lang=\"de\">\n<head>\n<meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    h.push_str("<title>stratum Report</title>\n");
    h.push_str(STYLE);
    h.push_str("</head>\n<body>\n");

    h.push_str("<h1>stratum Report</h1>\n");

    // Kopf: Werkzeug und Image.
    h.push_str("<section class=\"card\">\n<h2>Image</h2>\n<table class=\"kv\">\n");
    row(
        &mut h,
        "Werkzeug",
        &format!("{} {}", report.tool.name, report.tool.version),
    );
    row(
        &mut h,
        "Erstellt (Unix)",
        &report.generated_unix.to_string(),
    );
    row(&mut h, "Pfad", &report.image.path);
    row(&mut h, "Größe", &format!("{} Bytes", report.image.size));
    if let Some(hh) = &report.image.hashes {
        row(&mut h, "SHA-256", &hh.sha256);
        row(&mut h, "BLAKE3", &hh.blake3);
    }
    h.push_str("</table>\n</section>\n");

    // Partitionen.
    h.push_str("<section class=\"card\">\n<h2>Partitionen</h2>\n");
    h.push_str(&format!("<p>Schema: {:?}</p>\n", report.partitions.scheme));
    h.push_str("<table>\n<tr><th>#</th><th>Typ</th><th>Offset</th><th>Größe (Bytes)</th><th>Dateisystem</th></tr>\n");
    for p in &report.partitions.partitions {
        h.push_str("<tr>");
        cell(&mut h, &p.index.to_string());
        cell(&mut h, p.type_name);
        cell(&mut h, &p.start_offset.to_string());
        cell(&mut h, &p.size_bytes.to_string());
        cell(&mut h, &format!("{:?}", p.fs_hint));
        h.push_str("</tr>\n");
    }
    h.push_str("</table>\n</section>\n");

    // Windows-Installationen.
    for w in &report.windows {
        h.push_str(
            "<section class=\"card\">\n<h2>Windows-Installation</h2>\n<table class=\"kv\">\n",
        );
        row(&mut h, "Partition-Offset", &w.partition_offset.to_string());
        if let Some(c) = &w.computer_name {
            row(&mut h, "Rechnername", c);
        }
        if let Some(tz) = &w.timezone {
            let bias = tz
                .active_bias_minutes
                .map(|b| format!(" (Bias {b} min)"))
                .unwrap_or_default();
            row(&mut h, "Zeitzone", &format!("{}{}", tz.key_name, bias));
        }
        h.push_str("</table>\n");

        if !w.accounts.is_empty() {
            h.push_str("<h3>Konten</h3>\n<table>\n<tr><th>RID</th><th>Benutzername</th><th>NT-Hash</th><th>Passwort</th></tr>\n");
            for a in &w.accounts {
                h.push_str("<tr>");
                cell(&mut h, &a.rid.to_string());
                cell(&mut h, &a.username);
                cell(&mut h, &a.nt_hash);
                cell(&mut h, if a.has_password { "gesetzt" } else { "leer" });
                h.push_str("</tr>\n");
            }
            h.push_str("</table>\n");
        }
        push_warnings(&mut h, &w.warnings);
        h.push_str("</section>\n");
    }

    // Funde aller Domänen-Analyzer.
    {
        h.push_str("<section class=\"card\">\n<h2>Funde</h2>\n");
        if let Some(k) = &report.keywords {
            h.push_str(&format!(
                "<p>Begriffstabelle: {} (v{})</p>\n",
                esc(&k.table_name),
                k.table_version
            ));
        }
        h.push_str(&format!(
            "<p>{} Funde insgesamt</p>\n",
            report.findings.len()
        ));
        h.push_str("<table>\n<tr><th>Domäne</th><th>Name</th><th>Pfad</th><th>Offset</th><th>Kontext</th></tr>\n");
        for f in &report.findings {
            h.push_str("<tr>");
            cell(&mut h, &f.domain);
            cell(&mut h, &f.name);
            cell(&mut h, &f.source);
            cell(&mut h, &f.offset.map(|o| o.to_string()).unwrap_or_default());
            cell(
                &mut h,
                f.attributes
                    .get("kontext")
                    .or_else(|| f.attributes.get("hinweis"))
                    .map(String::as_str)
                    .unwrap_or(""),
            );
            h.push_str("</tr>\n");
        }
        h.push_str("</table>\n");
        h.push_str("</section>\n");
    }

    // Übergreifende Hinweise.
    if !report.warnings.is_empty() {
        h.push_str("<section class=\"card\">\n<h2>Hinweise</h2>\n");
        push_warnings(&mut h, &report.warnings);
        h.push_str("</section>\n");
    }

    h.push_str("</body>\n</html>\n");
    h
}

fn row(h: &mut String, key: &str, value: &str) {
    h.push_str("<tr><th>");
    h.push_str(&esc(key));
    h.push_str("</th><td>");
    h.push_str(&esc(value));
    h.push_str("</td></tr>\n");
}

fn cell(h: &mut String, value: &str) {
    h.push_str("<td>");
    h.push_str(&esc(value));
    h.push_str("</td>");
}

fn push_warnings(h: &mut String, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    h.push_str("<ul class=\"warn\">\n");
    for w in warnings {
        h.push_str("<li>");
        h.push_str(&esc(w));
        h.push_str("</li>\n");
    }
    h.push_str("</ul>\n");
}

/// HTML-Escaping der fünf kritischen Zeichen.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = "<style>\n\
:root{color-scheme:light dark}\n\
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:1.5rem;line-height:1.4;background:#f6f7f9;color:#1a1a1a}\n\
@media(prefers-color-scheme:dark){body{background:#15171a;color:#e6e6e6}.card{background:#1e2227!important;border-color:#2c313a!important}th{background:#252a31!important}}\n\
h1{font-size:1.5rem}h2{font-size:1.15rem;margin:0 0 .6rem}h3{font-size:1rem}\n\
.card{background:#fff;border:1px solid #e2e5ea;border-radius:10px;padding:1rem 1.2rem;margin:0 0 1.2rem;overflow-x:auto}\n\
table{border-collapse:collapse;width:100%;font-size:.86rem}\n\
th,td{text-align:left;padding:.35rem .55rem;border-bottom:1px solid #e2e5ea;vertical-align:top}\n\
th{background:#f0f2f5;font-weight:600;white-space:nowrap}\n\
table.kv th{width:14rem}\n\
td{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}\n\
.warn{color:#a15c00}\n\
</style>\n";
