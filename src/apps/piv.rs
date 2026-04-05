app!();

impl<'t> crate::Select<'t> for App<'t> {
    const RID: &'static [u8] = super::Rid::NIST;
    const PIX: &'static [u8] = super::Pix::PIV;
}

impl App<'_> {
    /// Pretty-print slot and PIN status.
    pub fn print_status(&mut self) -> crate::Result<()> {

        // Key slots: (display name, cert GET DATA tag, key ref for GENERAL AUTHENTICATE)
        const SLOTS: &[(&str, [u8; 3], u8)] = &[
            ("9A  PIV Authentication", [0x5F, 0xC1, 0x07], 0x9A),
            ("9C  Digital Signature",  [0x5F, 0xC1, 0x0A], 0x9C),
            ("9D  Key Management",     [0x5F, 0xC1, 0x0B], 0x9D),
            ("9E  Card Authentication",[0x5F, 0xC1, 0x01], 0x9E),
        ];

        println!("Key slots:");
        for (name, tag, key_ref) in SLOTS {
            let indicator = match (self.slot_has_cert(tag), self.slot_has_key(*key_ref)) {
                (true,  _)     => "certificate present",
                (false, true)  => "key present, no certificate",
                (false, false) => "empty",
            };
            println!("  {name}: {indicator}");
        }

        // PIN / PUK retry counters via VERIFY with no data (returns 63 CX or 90 00)
        println!();
        println!("PIN status:");
        match self.pin_retries(0x80) {
            Some(n) => println!("  PIN: {n} retries remaining"),
            None    => println!("  PIN: unknown"),
        }
        match self.pin_retries(0x81) {
            Some(n) => println!("  PUK: {n} retries remaining"),
            None    => println!("  PUK: unknown"),
        }

        Ok(())
    }

    /// Factory-reset the PIV applet (INS 0xFB, proprietary SoloKeys extension)
    pub fn reset(&mut self) -> crate::Result<()> {
        self.transport
            .call_iso(0x00, 0xFB, 0x00, 0x00, &[])
            .map(drop)
    }

    // ── internal helpers ─────────────────────────────────────────────────────

    /// GET DATA for a 3-byte PIV tag (0x5C 0x03 <tag>).
    /// Returns true if the slot contains a non-empty certificate.
    fn slot_has_cert(&mut self, tag: &[u8; 3]) -> bool {
        let data = [0x5C, 0x03, tag[0], tag[1], tag[2]];
        match self.transport.call_iso(0x00, 0xCB, 0x3F, 0xFF, &data) {
            Ok(resp) => {
                // Response is wrapped in 53 TLV; cert is in inner 70 TLV.
                // A slot is "populated" if any non-zero bytes are present inside 70.
                inner_tag_nonempty(&resp, 0x70)
            }
            Err(_) => false,
        }
    }

    /// Probe key presence via GENERAL AUTHENTICATE (INS 0x87) with an empty DAT (7C 00).
    /// PIV checks the key reference before validating the algorithm, so:
    ///   SW 6A 88 = no key in slot
    ///   anything else (69 82 security, 6A 80 wrong algo, …) = key exists
    fn slot_has_key(&mut self, key_ref: u8) -> bool {
        // Use ECC P-256 (0x11) as algo — wrong algo errors still confirm key presence.
        let dat = [0x7C, 0x00];
        match self.transport.call_iso(0x00, 0x87, 0x11, key_ref, &dat) {
            Ok(_) => true,
            Err(e) => {
                let msg = e.to_string();
                // 6A 88 = Referenced data not found → slot empty
                // 6A 86 = Incorrect P1-P2 → also treat as empty (key ref unknown)
                !msg.contains("(6A, 88)") && !msg.contains("(6A, 86)")
            }
        }
    }

    /// VERIFY with no data returns 63 CX (X = retries) or 90 00 (not set / verified).
    fn pin_retries(&mut self, key_ref: u8) -> Option<u8> {
        // VERIFY INS=0x20, P1=0x00, P2=key_ref, no data → error is expected, check SW
        // We use a raw ISO call and look for the "wrong" error that carries the counter.
        match self.transport.call_iso(0x00, 0x20, 0x00, key_ref, &[]) {
            Ok(_) => Some(3), // not blocked, assume 3 (already verified)
            Err(e) => {
                let msg = e.to_string();
                // "card signaled error ... (63, CX)" → X is retries
                parse_63cx(&msg)
            }
        }
    }
}

/// Recursively search TLV data for `target_tag`; return true if found with non-zero content.
fn inner_tag_nonempty(data: &[u8], target_tag: u8) -> bool {
    let mut pos = 0;
    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        if pos >= data.len() {
            break;
        }
        // Parse BER length
        let lb = data[pos] as usize;
        pos += 1;
        let len = if lb == 0x82 && pos + 1 < data.len() {
            let l = ((data[pos] as usize) << 8) | data[pos + 1] as usize;
            pos += 2;
            l
        } else if lb == 0x81 && pos < data.len() {
            let l = data[pos] as usize;
            pos += 1;
            l
        } else {
            lb
        };
        let end = pos + len;
        if end > data.len() {
            break;
        }
        let value = &data[pos..end];
        if tag == target_tag {
            return value.iter().any(|&b| b != 0);
        }
        // Recurse into any container (0x53 = PIV data object wrapper, or constructed bit set)
        if tag == 0x53 || tag & 0x20 != 0 {
            if inner_tag_nonempty(value, target_tag) {
                return true;
            }
        }
        pos = end;
    }
    false
}

/// Extract retry count from error strings like "card signaled error ... (63, C2)" → Some(2).
fn parse_63cx(msg: &str) -> Option<u8> {
    // Look for "(63, C" followed by a hex digit
    let marker = "(63, C";
    let pos = msg.find(marker)?;
    let after = &msg[pos + marker.len()..];
    let hex_char = after.chars().next()?;
    u8::from_str_radix(&hex_char.to_string(), 16).ok()
}
