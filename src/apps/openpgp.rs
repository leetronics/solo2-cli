use hex_literal::hex;

use crate::Result;

app!();

impl<'t> crate::Select<'t> for App<'t> {
    const RID: &'static [u8] = &hex!("D27600012401"); // full 6-byte OpenPGP AID
    const PIX: &'static [u8] = &[];
}

impl App<'_> {
    /// GET DATA 0x6E: Application Related Data (key slots, fingerprints, algo attributes)
    pub fn status(&mut self) -> Result<Vec<u8>> {
        self.transport.call_iso(0x00, 0xCA, 0x00, 0x6E, &[])
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
