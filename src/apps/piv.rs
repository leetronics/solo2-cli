app!();

impl<'t> crate::Select<'t> for App<'t> {
    const RID: &'static [u8] = super::Rid::NIST;
    const PIX: &'static [u8] = super::Pix::PIV;
}

impl App<'_> {
    /// Factory-reset the PIV applet (INS 0xFB, proprietary SoloKeys extension)
    pub fn reset(&mut self) -> crate::Result<()> {
        self.transport
            .call_iso(0x00, 0xFB, 0x00, 0x00, &[])
            .map(drop)
    }
}
