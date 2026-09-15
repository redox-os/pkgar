use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Seek, SeekFrom};

use crate::Error;

pub struct PackageUrlReader<'a> {
    client: &'a ureq::Agent,
    url: String,
    offset: u64,
}

impl<'a> PackageUrlReader<'a> {
    pub fn new(client: &'a ureq::Agent, url: &str) -> Self {
        Self {
            client,
            url: url.to_string(),
            offset: 0,
        }
    }

    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let end_offset = offset
            .checked_add(
                u64::try_from(
                    buf.len()
                        .checked_sub(1)
                        .ok_or(pkgar_core::Error::Overflow)?,
                )
                .map_err(pkgar_core::Error::TryFromInt)?,
            )
            .ok_or(pkgar_core::Error::Overflow)?;

        let range = format!("bytes={}-{}", offset, end_offset);

        let mut response = self.client.get(&self.url).header("Range", &range).call()?;

        // eprintln!(
        //     "Request {} from {} = {:?}",
        //     range,
        //     self.url,
        //     response.status()
        // );

        response
            .body_mut()
            .as_reader()
            .read_exact(buf)
            .map_err(|source| pkgar_keys::Error::Io {
                source,
                path: Some(self.url.clone().into()),
                context: "Downloading pkgar",
            })?;

        Ok(buf.len())
    }
}

impl<'a> Read for PackageUrlReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.read_at(self.offset, buf)
            .map_err(|e| IoError::other(e.to_string()))
    }
}

impl<'a> Seek for PackageUrlReader<'a> {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                self.offset = offset;
            }
            SeekFrom::Current(delta) => {
                if delta < 0 {
                    self.offset =
                        self.offset
                            .checked_sub(delta.unsigned_abs())
                            .ok_or_else(|| {
                                IoError::new(ErrorKind::InvalidInput, "Seeked before start")
                            })?;
                } else {
                    self.offset = self
                        .offset
                        .checked_add(delta as u64)
                        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Seek overflow"))?;
                }
            }
            SeekFrom::End(_) => {
                return Err(IoError::new(ErrorKind::Unsupported, "Unimplemented"));
            }
        }
        Ok(self.offset)
    }
}
