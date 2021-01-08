use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use blake3::Hasher;
use error_chain::bail;
use pkgar_core::{Entry, ENTRY_SIZE, Header, HEADER_SIZE};
use pkgar_keys::SecretKeyFile;
use sodiumoxide::crypto::sign;

use crate::{Error, READ_WRITE_HASH_BUF_SIZE, ResultExt};
use crate::ext::{copy_and_hash, EntryExt};

enum BuilderEntry {
    File {
        /// Path to regular file during build
        source: PathBuf,
        /// Target path for archive entry
        target: PathBuf,
        
        mode: u32,
    },
    
    Reader {
        source: Box<dyn Read>,
        target: PathBuf,
        mode: u32,
    },
    
    Symlink {
        /// Traget path for archive entry
        target: PathBuf,
        /// Link contents
        link: PathBuf,
        
        mode: u32,
    },
    
    /// An entry that has already been written to the data segment
    Written(Entry),
}

/// Builder pattern for constructing pkgar archives. Holds a list of entries
/// and consumes itself to construct an archive.
///
/// # Example
/// ```
/// use std::io::Cursor;
///
/// use pkgar_core::{PackageBuf, PackageSrc};
/// use pkgar_keys::SecretKeyFile;
/// use pkgar::PackageBuilder;
///
/// let (pkey, skey) = SecretKeyFile::new();
///
/// // It's possible to use a buffer instead of a file as the destination
/// let mut archive_dest = Cursor::new(Vec::new());
///
/// let mut builder = PackageBuilder::new(skey);
/// builder.file_reader(&b"some file contents"[..], "/path/to/unpack/to", 0o600);
/// builder.symlink("/path/to/unpack/2", "/path/to/link/to", 0o644);
/// builder.file_reader(&b"sorta hidden file contents"[..], "/path/to/link/to", 0o644);
/// builder.write_archive(&mut archive_dest)
///     .unwrap();
///
/// let archive = archive_dest.into_inner();
///
/// let mut src = pkgar_core::PackageBuf::new(&archive, &pkey.pkey)
///     .unwrap();
/// let entry = src.read_entries()
///     .unwrap()
///     .into_iter()
///     .find(|entry| entry.mode == 0o600 )
///     .unwrap();
/// assert_eq!(b"/path/to/unpack/to", entry.path_bytes());
/// ```
pub struct PackageBuilder {
    keys: SecretKeyFile,
    
    entries: Vec<BuilderEntry>,
}

impl PackageBuilder {
    pub fn new(keys: SecretKeyFile) -> PackageBuilder {
        PackageBuilder {
            keys,
            entries: Vec::new(),
        }
    }
    
    /// Add a regular file to this builder. `source` is the position of the
    /// file on the build system, while `target` is the file path used when
    /// extracting the archive.
    pub fn file(
        &mut self,
        source: impl AsRef<Path>,
        target: impl AsRef<Path>,
        mode: u32,
    ) {
        self.entries.push(
            BuilderEntry::File {
                source: source.as_ref().to_path_buf(),
                target: target.as_ref().to_path_buf(),
                mode,
            }
        );
    }
    
    /// Add a symlink to this builder. `target` is the file path of the link
    /// when extracting the archive, and `link` is the contents of the link.
    pub fn symlink(
        &mut self,
        target: impl AsRef<Path>,
        link: impl AsRef<Path>,
        mode: u32,
    ) {
        self.entries.push(
            BuilderEntry::Symlink {
                target: target.as_ref().to_path_buf(),
                link: link.as_ref().to_path_buf(),
                mode,
            }
        );
    }
    
    /// Much the same as [`PackageBuilder::file`], except stores a Reader
    /// instead of a file path.
    pub fn file_reader(
        &mut self,
        source: impl Read + 'static,
        target: impl AsRef<Path>,
        mode: u32,
    ) {
        self.entries.push(
            BuilderEntry::Reader {
                source: Box::new(source),
                target: target.as_ref().to_path_buf(),
                mode,
            }
        );
    }
    
    /// Consume this `PackageBuilder`, writing the head and data segments to
    /// separate writers.
    pub fn write_parts<W, X>(
        mut self,
        head: &mut W,
        data: &mut X,
    ) -> Result<(u64, u64), Error>
        where W: Write + Seek,
              X: Write,
    {
        Ok((self.write_data(data)?, self.write_head(head)?))
    }
    
    /// Consume this `PackageBuilder`, writing the head and data segments to
    /// the same writer.
    pub fn write_archive<W>(mut self, w: &mut W) -> Result<u64, Error>
        where W: Write + Seek,
    {
        let head_size = (HEADER_SIZE + (self.entries.len() * ENTRY_SIZE)) as u64;
        
        w.seek(SeekFrom::Start(head_size))?;
        let data_size = self.write_data(w)?;
        
        w.seek(SeekFrom::Start(0))?;
        if self.write_head(w)? != head_size {
            bail!("Head lengths did not match");
        } else {
            Ok(head_size + data_size)
        }
    }
    
    //WARN: Don't call this when the user can get mutable access again
    fn write_head<W>(&self, writer: &mut W) -> Result<u64, Error>
        where W: Write + Seek,
    {
        let secret_key = self.keys.key()
            .expect("PackageBuilder was passed encrypted keys");
        
        let mut hasher = Hasher::new();
        let mut offset = 0;
        
        writer.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        
        for entry in self.entries.iter() {
            match entry {
                BuilderEntry::Written(entry) => {
                    let entry_bytes = unsafe {
                        plain::as_bytes(entry)
                    };
                    
                    hasher.update(entry_bytes);
                    writer.write_all(entry_bytes)?;
                    offset += ENTRY_SIZE;
                }
                _ => panic!("write_head shouldn't reach unwritten"),
            }
        }
        
        let mut header = Header {
            signature: [0; 64],
            public_key: [0; 32],
            blake3: hasher.finalize().into(),
            count: self.entries.len() as u64,
        };
        
        header.public_key.copy_from_slice(
            secret_key.public_key().as_ref()
        );
        
        header.signature = sign::sign_detached(
            unsafe { &plain::as_bytes(&header)[64..] },
            &secret_key,
        ).0;
        
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(unsafe { plain::as_bytes(&header) })?;
        offset += HEADER_SIZE;
        
        Ok(offset as u64)
    }
    
    /// Assumes `writer` starts at position 0 when calculating offsets.
    /// Returns the total length of the data segment.
    fn write_data(&mut self, mut writer: &mut impl Write) -> Result<u64, Error> {
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        let mut offset = 0;
        
        for entry in self.entries.iter_mut() {
            //TODO: Check Modes
            //TODO: Refactor to reduce duplication
            *entry = match entry {
                BuilderEntry::File { source, target, mode } => {
                    let source_file = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&source)
                        .chain_err(|| source.as_path() )?;
                    
                    let (size, hash) = copy_and_hash(source_file, &mut writer, &mut buf)
                        .chain_err(|| source.as_path() )?;
                    
                    let entry = Entry::new(hash, offset, size, *mode, target)?;
                    offset += entry.size;
                    
                    BuilderEntry::Written(entry)
                },
                BuilderEntry::Reader { source, target, mode } => {
                    let (size, hash) = copy_and_hash(source, &mut writer, &mut buf)?;
                    
                    let entry = Entry::new(hash, offset, size, *mode, target)?;
                    offset += entry.size;
                    
                    BuilderEntry::Written(entry)
                },
                BuilderEntry::Symlink { target, link, mode } => {
                    let link_bytes = link.as_os_str().as_bytes();
                    let (size, hash) = copy_and_hash(link_bytes, &mut writer, &mut buf)?;
                    
                    let entry = Entry::new(hash, offset, size, *mode, target)?;
                    offset += entry.size;
                    
                    BuilderEntry::Written(entry)
                },
                BuilderEntry::Written(_) => panic!("write_data shouldn't reach written"),
            };
        }
        Ok(offset)
    }
}

