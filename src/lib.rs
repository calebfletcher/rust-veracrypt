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
    #[error("invalid header: {0}")]
    InvalidHeader(binrw::Error),
}

pub struct Volume<D: io::Read + io::Seek> {
    data: D,
    header: Option<VolumeHeader>,
    xts: Option<Xts128<Aes256>>,
}

impl Volume<File> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path).map_err(Error::FileOpenFailure)?;

        Ok(Self {
            data: file,
            header: None,
            xts: None,
        })
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

        // Setup header decryption
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

        // Decode header
        let header =
            VolumeHeader::read(&mut io::Cursor::new(header)).map_err(Error::InvalidHeader)?;

        // Set up data decryption
        let cipher_1 = Aes256::new(GenericArray::from_slice(&header.master_keys[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&header.master_keys[32..]));
        let xts = Xts128::<Aes256>::new(cipher_1, cipher_2);

        //xts.decrypt_area([64..], 448, 0, get_tweak_default);

        // Move to the start of the data area
        self.data
            .seek(io::SeekFrom::Start(header.master_key_scope_offset))
            .map_err(|_| Error::InvalidVolume)?;

        self.header.replace(header);
        self.xts.replace(xts);

        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Debug, BinRead)]
#[br(big)]
pub struct VolumeHeader {
    salt: [u8; 64],
    #[br(magic = b"VERA")]
    version: u16,
    minimum_program_version: u16,
    master_key_crc: u32,
    #[br(pad_before = 16)]
    hidden_volume_size: u64,
    volume_size: u64,
    master_key_scope_offset: u64,
    master_key_scope_size: u64,
    flags: u32,
    sector_size: u32,
    #[br(pad_before = 120)]
    header_checksum: u32,
    master_keys: [u8; 64], // NOTE: this assumes 2x256 bit keys (i.e. AES-256 mode)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
