use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use bytemuck::Zeroable;
use pkgar_core::{Entry, Header, PackageSrc, PublicKey};

use crate::ext::{DataReader, PackageSrcExt};
use crate::Error;

pub struct PackageFile {
    path: PathBuf,
    pub(crate) src: Option<(BufReader<File>, u64)>,
    header: Header,
    data: Option<(u64, u64, BufReader<DataReader>, u64)>,
}

impl Debug for PackageFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackageFile")
            .field("path", &self.path)
            .field("src", &self.src)
            .field("header", &self.header)
            .finish()
    }
}

impl PackageFile {
    pub fn new(path: impl AsRef<Path>, public_key: &PublicKey) -> Result<PackageFile, Error> {
        let path = path.as_ref().to_path_buf();

        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| Error::Io {
                source,
                path: Some(path.clone()),
                context: "Open",
            })?;

        let mut new = PackageFile {
            path,
            src: Some((BufReader::new(file), 0)),
            // Need a blank header to construct the PackageFile, since we need to
            //   use a method of PackageSrc in order to get the actual header...
            header: Header::zeroed(),
            data: None,
        };

        new.header = new.read_header(public_key)?;
        Ok(new)
    }
}

impl PackageSrc for PackageFile {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        if let Some((_, _, reader, _)) = self.data.take() {
            // pretty slow operation
            self.src = Some((BufReader::new(reader.into_inner().finish()), 0));
        }
        let Some((src, seek)) = &mut self.src else {
            return Err(Error::from(pkgar_core::Error::NotSupported));
        };
        if *seek != offset {
            src.seek(SeekFrom::Start(offset))
                .map_err(|source| Error::Io {
                    source,
                    path: None,
                    context: "Seek",
                })?;
            *seek = offset;
        }
        src.read_exact(buf).map_err(|source| Error::Io {
            source,
            path: None,
            context: "Read",
        })?;

        *seek += buf.len() as u64;

        Ok(buf.len())
    }

    fn read_data(&mut self, entry: Entry, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let Some((data_offset, data_len, reader, seek)) = &mut self.data else {
            return Err(Error::from(pkgar_core::Error::NotInitialized));
        };
        let end = <Self as PackageSrc>::calculate_end(entry, offset, buf)?;
        let offset = offset + entry.offset + *data_offset;
        if *seek != offset {
            todo!();
            // reader
            //     .seek(SeekFrom::Start(offset))
            //     .map_err(|source| Error::Io {
            //         source,
            //         path: None,
            //         context: "Seek",
            //     })?;
        }
        reader
            .read_exact(&mut buf[..end])
            .map_err(|source| Error::Io {
                source,
                path: None,
                context: "Read",
            })?;
        *seek += end as u64;

        Ok(end)
    }

    fn init_data_read(&mut self, data_offset: u64, data_len: u64) -> Result<(), Self::Err> {
        if let Some((src, _)) = self.src.take() {
            let mut file = src.into_inner();
            file.seek(SeekFrom::Start(data_offset))
                .map_err(|source| Error::Io {
                    source,
                    path: None,
                    context: "Seek",
                })?;
            let reader = DataReader::new(self.header.flags.packaging(), file);
            let reader = BufReader::new(reader);
            self.data = Some((data_offset, data_len, reader, data_offset));
        }
        Ok(())
    }
}

impl PackageSrcExt for PackageFile {
    fn path(&self) -> &Path {
        &self.path
    }
}
