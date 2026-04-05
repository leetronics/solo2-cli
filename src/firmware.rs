//! Signed firmware releases for Solo 2 devices.
//!
use anyhow::anyhow;
/// Version of a firmware
pub use lpc55::secure_binary::Version;

use crate::Result;

pub mod github;

#[derive(Clone, Eq, PartialEq)]
pub struct Firmware {
    content: Vec<u8>,
    version: Version,
}

impl Firmware {
    pub fn version(&self) -> Version {
        self.version
    }

    // TODO: To implement this, upstream `lpc55` library needs to gain support
    // for decoding signed SB2.1 files.
    //
    // /// Returns Ok if the firmware has a valid signature.
    // pub fn verify(&self) -> Result<()> {
    // }

    pub fn write_to<'a>(
        &self,
        bootloader: &lpc55::Bootloader,
        progress: Option<&'a dyn Fn(usize)>,
    ) {
        bootloader.receive_sb_file(&self.content, progress);
    }

    /// This is not the best we can do; should instead verify the Firmware data is valid, and the signatures verify against [`R1`][crate::pki::Authority::R1].
    pub fn verify_hexhash(&self, sha256_hex_hash: &str) -> Result<()> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.content);

        (hex::encode(hasher.finalize()) == sha256_hex_hash)
            .then(|| ())
            .ok_or_else(|| anyhow!("Sha2 hash on downloaded firmware did not verify!"))
    }

    pub fn new(content: Vec<u8>) -> Result<Self> {
        let header_bytes = &content.as_slice()[..96];
        let header = lpc55::secure_binary::Sb2Header::from_bytes(header_bytes)?;

        Ok(Self {
            content,
            version: header.product_version(),
        })
    }

    pub fn read_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::new(std::fs::read(path)?)
    }

    pub fn download_latest() -> Result<Self> {
        let specs = github::Release::fetch_spec()?;
        specs.fetch_firmware()
    }

    pub fn len(&self) -> usize {
        self.content.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

const FLASH_ALIGN: usize = 512;

/// Flash a raw binary (produced by `cargo objcopy -- -O binary`).
/// Pads to 512-byte boundary, erases [0x00000000..len), then writes.
pub fn write_flash_bin(
    bootloader: &lpc55::Bootloader,
    data: &[u8],
    progress: Option<&dyn Fn(usize)>,
) {
    let mut padded = data.to_vec();
    let overshoot = padded.len() % FLASH_ALIGN;
    if overshoot > 0 {
        padded.resize(padded.len() + FLASH_ALIGN - overshoot, 0);
    }
    bootloader.erase_flash(0x0000_0000, padded.len());
    bootloader.write_memory(0x0000_0000, padded);
    if let Some(cb) = progress {
        cb(data.len());
    }
}
