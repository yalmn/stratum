//! Hält die Quellrevision im Binary fest, damit jeder Report belegt, mit
//! welchem Stand er erzeugt wurde. Ohne Git (etwa aus einem Quellarchiv)
//! steht dort `unbekannt`.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

fn main() {
    let revision = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unbekannt".into());
    // Nicht committete Änderungen an versionierten Dateien. Lokale, nie
    // versionierte Dateien wie die Anweisungsdateien zählen nicht.
    let dirty = match git(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(s) if s.is_empty() => "nein",
        Some(_) => "ja",
        None => "unbekannt",
    };
    println!("cargo:rustc-env=STRATUM_REVISION={revision}");
    println!("cargo:rustc-env=STRATUM_REVISION_GEAENDERT={dirty}");

    // Neu bauen, wenn sich Stand oder Quellen irgendeiner Crate ändern.
    if let Some(git_dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        for f in ["HEAD", "index", "packed-refs", "refs/heads"] {
            let p = Path::new(&git_dir).join(f);
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
    for dir in [
        "src",
        "../core",
        "../mmap",
        "../registry",
        "../search",
        "../ntfs",
        "../creds",
        "../analysis",
        "../Cargo.lock",
    ] {
        println!("cargo:rerun-if-changed={dir}");
    }
}
