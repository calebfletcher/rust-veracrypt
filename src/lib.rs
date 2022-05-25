use std::{fs::File, io, path::Path};

use aes::{
    cipher::{generic_array::GenericArray, KeyInit},
    Aes256,
};
use binrw::BinRead;
use crc::{Crc, CRC_32_ISO_HDLC};
use xts_mode::{get_tweak_default, Xts128};

static CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("file open error: {0}")]
    FileOpenFailure(io::Error),
    #[error("invalid volume")]
    InvalidVolume,
    #[error("invalid key")]
    InvalidKey,
}

pub struct Volume<D: io::Read + io::Seek> {
    data: D,
}

impl Volume<File> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path).map_err(Error::FileOpenFailure)?;

        Ok(Self { data: file })
    }
}

impl<D: io::Read + io::Seek> Volume<D> {
    pub fn decrypt(&mut self, password: &str) -> Result<(), Error> {
        // Go to the start of the volume
        self.data.rewind().map_err(|_| Error::InvalidVolume)?;

        // Read header
        let mut header = [0; 512];
        self.data
            .read_exact(&mut header)
            .map_err(|_| Error::InvalidVolume)?;

        // Read salt from header
        let salt = &header[0..64];

        // Derive keys from password
        let rounds = 500000;
        let mut key = [0; 64];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(password.as_bytes(), salt, rounds, &mut key);

        // Setup AES XTS decryption
        let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..]));
        let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

        // Decrypt header
        xts.decrypt_area(&mut header[64..], 448, 0, get_tweak_default);

        // Check magic value
        if &header[64..68] != "VERA".as_bytes() {
            return Err(Error::InvalidKey);
        }

        // Check CRC
        let chk = CRC.checksum(&header[256..512]);
        if header[72..76] != chk.to_be_bytes() {
            return Err(Error::InvalidKey);
        }
        let chk = CRC.checksum(&header[64..252]);
        if header[252..256] != chk.to_be_bytes() {
            return Err(Error::InvalidKey);
        }

        Ok(())
    }
}

#[derive(Debug, BinRead)]
pub struct VolumeFormat {
    _salt: [u8; 64],
    _offset: binrw::PosValue<()>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
