use std::{fs::File, io, path::Path};

use aes::{
    cipher::{generic_array::GenericArray, KeyInit},
    Aes256,
};
use binrw::BinRead;
use crc::{Crc, CRC_32_ISO_HDLC};
use fscommon::BufStream;
use xts_mode::{get_tweak_default, Xts128};

static CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

type MountedFilesystem<D> = fatfs::FileSystem<BufStream<MountedVolume<D>>>;

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

pub struct UnmountedVolume<D: io::Read + io::Write + io::Seek> {
    data: D,
}

pub struct MountedVolume<D: io::Read + io::Write + io::Seek> {
    data: D,
    header: VolumeHeader,
    xts: Xts128<Aes256>,
}

impl UnmountedVolume<File> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path).map_err(Error::FileOpenFailure)?;

        Ok(Self { data: file })
    }
}

impl<D: io::Read + io::Write + io::Seek> UnmountedVolume<D> {
    pub fn mount(mut self, password: &str) -> Result<MountedFilesystem<D>, Error> {
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

        // Move to the start of the data area
        self.data
            .seek(io::SeekFrom::Start(header.master_key_scope_offset))
            .map_err(|_| Error::InvalidVolume)?;

        // Load filesystem
        let buf_stream = BufStream::new(MountedVolume {
            data: self.data,
            header,
            xts,
        });
        let fs = fatfs::FileSystem::new(buf_stream, fatfs::FsOptions::new()).unwrap();

        Ok(fs)
    }
}

impl<D: io::Read + io::Write + io::Seek> io::Read for MountedVolume<D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let current_pos = self.data.stream_position()? as usize;

        const DATA_UNIT_SIZE: usize = 512;
        let mut temp_buffer = [0; DATA_UNIT_SIZE as usize];

        // Calculate data unit boundaries
        let base_offset = (current_pos / DATA_UNIT_SIZE) * DATA_UNIT_SIZE;
        let total_bytes_to_read = current_pos + buf.len() - base_offset;
        let d = total_bytes_to_read / DATA_UNIT_SIZE;
        let r = total_bytes_to_read % DATA_UNIT_SIZE;
        let data_units_to_read = if r > 0 { d + 1 } else { d };

        // Move backwards so we end up on a data unit boundary
        let read_offset = current_pos - base_offset;
        self.data
            .seek(io::SeekFrom::Current(-(read_offset as i64)))?;
        let read_len = buf.len();

        let mut bytes_written = 0;
        for i in 0..data_units_to_read {
            // Read data unit
            self.data.read_exact(&mut temp_buffer)?;

            // Decrypt
            let sector_size = self.header.sector_size.try_into().unwrap();
            self.xts.decrypt_area(
                &mut temp_buffer,
                sector_size,
                (current_pos as usize / sector_size).try_into().unwrap(),
                get_tweak_default,
            );

            // Copy to user's buffer
            match i {
                0 => {
                    // First data unit
                    // copy [.......xxx] into [xxx------]
                    let num_bytes_of_interest = (DATA_UNIT_SIZE - read_offset).min(read_len);
                    buf[0..num_bytes_of_interest].copy_from_slice(
                        &temp_buffer[read_offset..read_offset + num_bytes_of_interest],
                    );
                    bytes_written += num_bytes_of_interest;
                }
                _ if i == data_units_to_read - 1 => {
                    // Last data unit
                    // copy [xxxx.......] into [-------xxxx]
                    let num_bytes_of_interest = total_bytes_to_read % DATA_UNIT_SIZE;
                    buf[read_len - num_bytes_of_interest..]
                        .copy_from_slice(&temp_buffer[0..num_bytes_of_interest]);
                    bytes_written += num_bytes_of_interest;
                }
                _ => {
                    // Middle data unit
                    // copy entire contents
                    buf[bytes_written..bytes_written + DATA_UNIT_SIZE]
                        .copy_from_slice(&temp_buffer);
                }
            }
        }

        Ok(bytes_written)
    }
}

impl<D: io::Read + io::Write + io::Seek> io::Write for MountedVolume<D> {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        // TODO: Encrypt data
        //unimplemented!();
        Ok(1)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.data.flush()
    }
}

impl<D: io::Read + io::Write + io::Seek> io::Seek for MountedVolume<D> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let current_pos = self.data.stream_position()?;
        let data_start_pos = self.header.master_key_scope_offset;
        let data_len = self.header.master_key_scope_size;

        // Modify the desired position based on where the filesystem data starts
        let new_pos = match pos {
            io::SeekFrom::Start(n) => data_start_pos + n,
            io::SeekFrom::End(n) => ((data_start_pos + data_len) as i64 - n) as u64,
            io::SeekFrom::Current(n) => (current_pos as i64 + n) as u64,
        };

        // Seek the volume
        self.data
            .seek(io::SeekFrom::Start(new_pos))
            .map(|pos| pos - data_start_pos)
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
    master_keys: [u8; 64], // NOTE: This assumes 2x256 bit keys (i.e. AES-256 mode)
}
