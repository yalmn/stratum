//! Begrenzte Suche nach IP-Literalen in ASCII und UTF-16LE.
//! Die Adressen werden syntaktisch geprüft, nicht als Netzwerkaktivität bewertet.

use std::io::{self, Write};
use std::net::{IpAddr, SocketAddrV4};

/// Ein IP-Literal mit seiner logischen Byteposition.
#[derive(Debug, serde::Serialize)]
pub struct IpTreffer {
    /// Normalisierte Adresse.
    pub adresse: String,
    /// Originaltext ohne Port oder umgebende Klammern.
    pub original: String,
    /// IPv4 oder IPv6.
    pub art: &'static str,
    /// Byteposition ab Dateianfang.
    pub offset: u64,
    /// Länge des Originaltexts in Bytes.
    pub laenge: u64,
    /// ASCII oder UTF-16LE.
    pub kodierung: &'static str,
}

/// Ergebnis und tatsächlicher Suchumfang.
#[derive(Debug, serde::Serialize)]
pub struct IpSuche {
    /// Höchstens 500 Treffer, einschließlich wiederholter Vorkommen.
    pub treffer: Vec<IpTreffer>,
    /// Tatsächlich untersuchte Bytes.
    pub gelesen: u64,
    /// Dateiende ohne Begrenzung erreicht.
    pub vollstaendig: bool,
}

#[derive(Default)]
struct Token {
    text: Vec<u8>,
    start: u64,
    zu_lang: bool,
}

impl Token {
    fn byte(
        &mut self,
        b: u8,
        offset: u64,
        stride: u64,
        encoding: &'static str,
    ) -> Option<IpTreffer> {
        if b.is_ascii_alphanumeric() || b".:_%-".contains(&b) {
            if self.text.is_empty() && !self.zu_lang {
                self.start = offset;
            }
            if self.text.len() < 128 && !self.zu_lang {
                self.text.push(b);
            } else {
                self.text.clear();
                self.zu_lang = true;
            }
            None
        } else {
            self.ende(stride, encoding)
        }
    }

    fn ende(&mut self, stride: u64, encoding: &'static str) -> Option<IpTreffer> {
        let result = if self.zu_lang {
            None
        } else {
            self.treffer(stride, encoding)
        };
        self.text.clear();
        self.zu_lang = false;
        result
    }

    fn treffer(&self, stride: u64, encoding: &'static str) -> Option<IpTreffer> {
        let text = std::str::from_utf8(&self.text).ok()?.trim_end_matches('.');
        if !text.contains('.') && !text.contains(':') {
            return None;
        }
        let (ip, original) = match text.parse::<IpAddr>() {
            Ok(ip) => (ip, text),
            Err(_) => {
                let socket = text.parse::<SocketAddrV4>().ok()?;
                (IpAddr::V4(*socket.ip()), text.split_once(':')?.0)
            }
        };
        Some(IpTreffer {
            adresse: ip.to_string(),
            original: original.to_string(),
            art: if ip.is_ipv4() { "IPv4" } else { "IPv6" },
            offset: self.start,
            laenge: original.len() as u64 * stride,
            kodierung: encoding,
        })
    }
}

/// Streaming-Scanner, auch über Blockgrenzen und ungerade UTF-16-Positionen.
pub struct IpScanner {
    tokens: [Token; 3],
    vorher: Option<u8>,
    ergebnis: IpSuche,
    limit: u64,
    gestoppt: bool,
}

impl IpScanner {
    /// Neuer Scanner mit einer maximalen Bytezahl.
    pub fn neu(limit: u64) -> Self {
        Self {
            tokens: Default::default(),
            vorher: None,
            ergebnis: IpSuche {
                treffer: Vec::new(),
                gelesen: 0,
                vollstaendig: false,
            },
            limit,
            gestoppt: false,
        }
    }

    /// Ob die Byte- oder Treffergrenze erreicht wurde.
    pub fn begrenzt(&self) -> bool {
        self.gestoppt
    }

    /// Abschließen. Nur am echten Dateiende werden offene Tokens ausgewertet.
    pub fn abschliessen(mut self, dateiende: bool) -> IpSuche {
        if dateiende && !self.gestoppt {
            for (index, token) in self.tokens.iter_mut().enumerate() {
                // Eine offene UTF-16-Folge mit fehlendem letzten High-Byte
                // darf keinen gekürzten, scheinbar gültigen Treffer liefern.
                if index > 0 && self.ergebnis.gelesen % 2 != (index - 1) as u64 {
                    continue;
                }
                if let Some(hit) = token.ende(
                    if index == 0 { 1 } else { 2 },
                    if index == 0 { "ASCII" } else { "UTF-16LE" },
                ) {
                    if self.ergebnis.treffer.len() == 500 {
                        self.gestoppt = true;
                        break;
                    }
                    self.ergebnis.treffer.push(hit);
                }
            }
        }
        self.ergebnis.vollstaendig = dateiende && !self.gestoppt;
        self.ergebnis
            .treffer
            .sort_by_key(|t| (t.offset, t.kodierung));
        self.ergebnis
    }
}

impl Write for IpScanner {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for &b in buf {
            if self.ergebnis.gelesen >= self.limit || self.ergebnis.treffer.len() >= 500 {
                self.gestoppt = true;
                return Err(io::Error::other("IP-Suchgrenze erreicht"));
            }
            let offset = self.ergebnis.gelesen;
            self.ergebnis.gelesen += 1;
            if let Some(hit) = self.tokens[0].byte(b, offset, 1, "ASCII") {
                self.ergebnis.treffer.push(hit);
            }
            if let Some(lo) = self.vorher {
                let slot = 1 + ((offset - 1) % 2) as usize;
                let character = if b == 0 { lo } else { 0 };
                if let Some(hit) = self.tokens[slot].byte(character, offset - 1, 2, "UTF-16LE") {
                    if self.ergebnis.treffer.len() == 500 {
                        self.gestoppt = true;
                        return Err(io::Error::other("IP-Suchgrenze erreicht"));
                    }
                    self.ergebnis.treffer.push(hit);
                }
            }
            self.vorher = Some(b);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adressen_und_falsche_tokens() {
        let mut s = IpScanner::neu(10000);
        s.write_all(b"192.0.2.1:443 [2001:DB8::1]:80 999.2.3.4 1.2.3.4.5 host192.0.2.2 001.2.3.4 ::ffff:192.0.2.3 10.0.0.1.").unwrap();
        let r = s.abschliessen(true);
        assert!(r.vollstaendig);
        assert_eq!(
            r.treffer
                .iter()
                .map(|h| h.adresse.as_str())
                .collect::<Vec<_>>(),
            ["192.0.2.1", "2001:db8::1", "::ffff:192.0.2.3", "10.0.0.1"]
        );
        assert_eq!(r.treffer[0].laenge, 9);
    }
    #[test]
    fn utf16_und_blockgrenzen() {
        let mut b = b"192.0.2.1  ".to_vec();
        let start = b.len() as u64;
        b.extend("2001:db8::2".encode_utf16().flat_map(u16::to_le_bytes));
        for size in 1..=b.len() {
            let mut s = IpScanner::neu(10000);
            for chunk in b.chunks(size) {
                s.write_all(chunk).unwrap();
            }
            let r = s.abschliessen(true);
            assert_eq!(r.treffer.len(), 2);
            assert_eq!(r.treffer[1].offset, start);
            assert_eq!(r.treffer[1].kodierung, "UTF-16LE");
            assert_eq!(r.treffer[1].laenge, 22);
        }
    }
    #[test]
    fn begrenzte_tokens_werden_nicht_als_vollstaendig_gedeutet() {
        let mut s = IpScanner::neu(9);
        assert!(s.write_all(b"192.0.2.123").is_err());
        assert!(s.begrenzt());
        assert!(s.abschliessen(false).treffer.is_empty());
        let mut s = IpScanner::neu(10000);
        let mut b = vec![b'x'; 1024];
        b.extend(b"192.0.2.1 ");
        s.write_all(&b).unwrap();
        assert!(s.abschliessen(true).treffer.is_empty());
        let mut b: Vec<_> = "192.0.2.123"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        b.pop();
        let mut s = IpScanner::neu(10000);
        s.write_all(&b).unwrap();
        assert!(s.abschliessen(true).treffer.is_empty());
        let mut s = IpScanner::neu(10000);
        assert!(s.write_all(&b"192.0.2.1 ".repeat(501)).is_err());
        let r = s.abschliessen(false);
        assert_eq!(r.treffer.len(), 500);
        assert!(!r.vollstaendig);
    }
}
