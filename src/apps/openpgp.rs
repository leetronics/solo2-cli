use hex_literal::hex;

use crate::Result;

app!();

impl<'t> crate::Select<'t> for App<'t> {
    const RID: &'static [u8] = &hex!("D27600012401"); // full 6-byte OpenPGP AID
    const PIX: &'static [u8] = &[];
}

impl App<'_> {
    /// GET DATA 0x6E: Application Related Data
    pub fn status(&mut self) -> Result<Vec<u8>> {
        self.transport.call_iso(0x00, 0xCA, 0x00, 0x6E, &[])
    }

    /// Pretty-print the application related data.
    pub fn print_status(&mut self) -> Result<()> {
        let data = self.status()?;

        let mut sig_algo = String::new();
        let mut dec_algo = String::new();
        let mut aut_algo = String::new();
        let mut pw_status: Vec<u8> = Vec::new();
        let mut fingerprints: Vec<u8> = Vec::new();
        let mut timestamps: Vec<u8> = Vec::new();
        let mut key_info: Vec<u8> = Vec::new();
        let mut uif = [0u8; 3]; // sig, dec, aut

        for item in TlvIter::new(&data) {
            if item.tag == 0x73 {
                for inner in TlvIter::new(item.value) {
                    match inner.tag {
                        0xC1 => sig_algo = fmt_algo(inner.value),
                        0xC2 => dec_algo = fmt_algo(inner.value),
                        0xC3 => aut_algo = fmt_algo(inner.value),
                        0xC4 => pw_status = inner.value.to_vec(),
                        0xC5 => fingerprints = inner.value.to_vec(),
                        0xCD => timestamps = inner.value.to_vec(),
                        0xDE => key_info = inner.value.to_vec(),
                        0xD6 => uif[0] = inner.value.first().copied().unwrap_or(0),
                        0xD7 => uif[1] = inner.value.first().copied().unwrap_or(0),
                        0xD8 => uif[2] = inner.value.first().copied().unwrap_or(0),
                        _ => {}
                    }
                }
            }
        }

        let key_statuses: Vec<(u8, u8)> =
            key_info.chunks_exact(2).map(|c| (c[0], c[1])).collect();

        let slots = [
            ("Signature",      0usize, 1u8, &sig_algo, uif[0]),
            ("Decryption",     1,      2u8, &dec_algo, uif[1]),
            ("Authentication", 2,      3u8, &aut_algo, uif[2]),
        ];

        println!("Key slots:");
        for (name, idx, key_ref, algo, uif_byte) in &slots {
            let status = key_statuses
                .iter()
                .find(|(r, _)| *r == *key_ref)
                .map(|(_, s)| *s)
                .unwrap_or(0);

            let fp = fingerprints
                .get(idx * 20..(idx + 1) * 20)
                .filter(|fp| !fp.iter().all(|b| *b == 0))
                .map(|fp| {
                    fp.iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":")
                });

            let ts = timestamps
                .get(idx * 4..(idx + 1) * 4)
                .and_then(|t| <[u8; 4]>::try_from(t).ok())
                .map(u32::from_be_bytes)
                .filter(|&s| s != 0)
                .map(fmt_unix);

            let status_str = match status {
                0 => "no key",
                1 => "generated on device",
                2 => "generated on device",
                3 => "imported",
                _ => "unknown",
            };

            let touch = if uif_byte & 0x01 != 0 { "required" } else { "not required" };

            println!("  {name} ({algo}):");
            println!("    Status:      {status_str}");
            if let Some(fp) = &fp {
                println!("    Fingerprint: {fp}");
            }
            if let Some(ts) = &ts {
                println!("    Generated:   {ts}");
            }
            println!("    Touch (UIF): {touch}");
        }

        if pw_status.len() >= 7 {
            println!();
            println!("PIN status:");
            println!(
                "  PW1 (user):  max {} bytes, {} retries left",
                pw_status[1], pw_status[4]
            );
            println!(
                "  RC  (reset): max {} bytes, {} retries left",
                pw_status[2], pw_status[5]
            );
            println!(
                "  PW3 (admin): max {} bytes, {} retries left",
                pw_status[3], pw_status[6]
            );
        }

        Ok(())
    }

    /// Factory reset: TERMINATE DF (E6) then ACTIVATE FILE (44)
    pub fn reset(&mut self) -> Result<()> {
        self.transport
            .call_iso(0x00, 0xE6, 0x00, 0x00, &[])
            .map(drop)?;
        self.transport
            .call_iso(0x00, 0x44, 0x00, 0x00, &[])
            .map(drop)
    }
}

// ── TLV iterator ─────────────────────────────────────────────────────────────

struct TlvIter<'a>(&'a [u8]);

struct TlvEntry<'a> {
    tag: u32,
    value: &'a [u8],
}

impl<'a> TlvIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = TlvEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = self.0;
        if buf.is_empty() {
            return None;
        }
        let mut pos = 0;

        // Parse tag (1–3 bytes, BER-TLV)
        let b0 = buf[pos] as u32;
        pos += 1;
        let tag = if b0 & 0x1F == 0x1F {
            let b1 = *buf.get(pos)? as u32;
            pos += 1;
            if b1 & 0x80 != 0 {
                let b2 = *buf.get(pos)? as u32;
                pos += 1;
                (b0 << 16) | (b1 << 8) | b2
            } else {
                (b0 << 8) | b1
            }
        } else {
            b0
        };

        // Parse length (1–3 bytes)
        let lb = *buf.get(pos)? as usize;
        pos += 1;
        let len = if lb == 0x81 {
            let l = *buf.get(pos)? as usize;
            pos += 1;
            l
        } else if lb == 0x82 {
            let hi = *buf.get(pos)? as usize;
            let lo = *buf.get(pos + 1)? as usize;
            pos += 2;
            (hi << 8) | lo
        } else {
            lb
        };

        let end = pos.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        let value = &buf[pos..end];
        self.0 = &buf[end..];
        Some(TlvEntry { tag, value })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fmt_unix(secs: u32) -> String {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    OffsetDateTime::from_unix_timestamp(secs as i64)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| format!("unix:{secs}"))
}

fn fmt_algo(data: &[u8]) -> String {
    if data.is_empty() {
        return "unknown".to_string();
    }
    match data[0] {
        0x01 => {
            let bits = data
                .get(1..3)
                .and_then(|b| <[u8; 2]>::try_from(b).ok())
                .map(u16::from_be_bytes)
                .unwrap_or(0);
            format!("RSA-{bits}")
        }
        0x13 => format!("ECDSA/{}", oid_name(&data[1..])),
        0x12 => format!("ECDH/{}", oid_name(&data[1..])),
        0x16 => format!("EdDSA/{}", oid_name(&data[1..])),
        id => format!("algo({id:#04x})"),
    }
}

fn oid_name(data: &[u8]) -> &'static str {
    // Known OID byte sequences (DER body, without tag 0x06 / length prefix).
    // A trailing format byte (e.g. 0xFF) may follow; use starts_with().
    const KNOWN: &[(&[u8], &str)] = &[
        // Ed25519  — 1.3.6.1.4.1.11591.15.1
        (&[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01], "Ed25519"),
        // X25519   — 1.3.6.1.4.1.3029.1.5.1
        (&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01], "X25519"),
        // NIST P-256 — 1.2.840.10045.3.1.7
        (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], "NIST P-256"),
        // NIST P-384 — 1.3.132.0.34
        (&[0x2b, 0x81, 0x04, 0x00, 0x22], "NIST P-384"),
        // NIST P-521 — 1.3.132.0.35
        (&[0x2b, 0x81, 0x04, 0x00, 0x23], "NIST P-521"),
    ];
    for &(oid, name) in KNOWN {
        if data.starts_with(oid) {
            return name;
        }
    }
    "unknown curve"
}
