use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use blake3::Hasher;
use error_chain::bail;
use sodiumoxide::crypto::sign;

use crate::{
    check_path,
    copy_and_hash,
    core::{Entry, ENTRY_SIZE, Header, HEADER_SIZE, Mode},
    EntryExt,
    Error,
    keys::SecretKeyFile,
    READ_WRITE_HASH_BUF_SIZE,
    ResultExt,
};

#[derive(Debug)]
struct BuilderEntry {
    /// Target path for archive entry
    target: PathBuf,
    mode: Mode,
    
    kind: BuilderEntryKind,
}

impl BuilderEntry {
    // Verify inputs to ensure that incorrect packages are not built by mistake
    fn new(
        target: impl AsRef<Path>,
        mode: Mode,
        kind: BuilderEntryKind,
    ) -> Result<BuilderEntry, Error> {
        let mut entry = BuilderEntry {
            target: target.as_ref().to_path_buf(),
            mode: mode.perm(),
            kind,
        };
        check_path(&entry.target)?;
        
        match entry.kind {
            BuilderEntryKind::File(_) | BuilderEntryKind::Reader(_) => {
                entry.mode |= Mode::FILE;
            },
            BuilderEntryKind::Symlink(_) => {
                entry.mode |= Mode::SYMLINK;
            },
            BuilderEntryKind::Written(_) =>
                unreachable!("Passed a BuilderEntryKind::Written to BuilderEntryKind::new"),
        }
        Ok(entry)
    }
}

enum BuilderEntryKind {
    /// Path to regular file during build
    File(PathBuf),
    
    Reader(Box<dyn Read>),
    
    /// Link contents
    Symlink(PathBuf),
    
    /// An entry that has already been written to the data segment
    Written(Entry),
}

impl fmt::Debug for BuilderEntryKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use BuilderEntryKind::*;
        write!(f, "BuilderEntryKind::{}", match self {
            File(p) => format!("File({:?})", p),
            Reader(_) => String::from("Reader(_)"),
            Symlink(p) => format!("Symlink({:?})", p),
            Written(e) => format!("Written({:?})", e),
        })
    }
}

/// Builder pattern for constructing pkgar archives. Holds a list of entries
/// and consumes itself to construct an archive.
///
/// [`PackageBuilder::file`], [`PackageBuilder::symlink`], and
/// [`PackageBuilder::file_reader`] all take a `target` and `mode`
/// parameter. `target` is the **relative** path that will be stored in the
/// archive (the builder will fail on write if this path is invalid), and
/// `mode` is a Unix mode. They return `&mut self` for slightly more convenient
/// chaining as seen in the example;
///
/// # Example
/// ```
/// use std::io::Cursor;
///
/// use pkgar_core::Mode;
/// use pkgar_keys::SecretKeyFile;
/// use pkgar::PackageBuilder;
///
/// let (pkey, skey) = SecretKeyFile::new();
///
/// // It's possible to use a buffer instead of a file as the destination
/// let mut archive_dest = Cursor::new(Vec::new());
///
/// let mut builder = PackageBuilder::new(skey);
/// builder.file_reader(
///         &b"some file contents"[..],
///         "path/to/unpack/to",
///         Mode::from_bits_truncate(0o600)).unwrap()
///     .symlink(
///         "path/to/link/to",
///         "path/to/unpack/2",
///         Mode::from_bits_truncate(0o644)).unwrap()
///     .file_reader(
///         &b"sorta hidden file contents"[..],
///         "path/to/link/to",
///         Mode::from_bits_truncate(0o644)).unwrap();
///
/// builder.write_archive(&mut archive_dest)
///     .unwrap();
/// #
/// # use pkgar_core::{PackageBuf, PackageHead};
/// # let archive = archive_dest.into_inner();
///
/// # let mut src = PackageBuf::new(&archive, &pkey.pkey)
/// #    .unwrap();
/// # let entry = src.entries()
/// #    .find(|entry| entry.mode().unwrap().perm() == Mode::from_bits(0o600).unwrap() )
/// #    .unwrap();
/// # assert_eq!(b"path/to/unpack/to", entry.path_bytes());
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
    /// file on the build system.
    pub fn file(
        &mut self,
        source: impl AsRef<Path>,
        target: impl AsRef<Path>,
        mode: Mode,
    ) -> Result<&mut PackageBuilder, Error> {
        self.entries.push(
            BuilderEntry::new(
                target, mode,
                BuilderEntryKind::File(source.as_ref().to_path_buf()),
            )?
        );
        Ok(self)
    }
    
    /// Add a symlink to this builder. `link` is the contents of the link.
    pub fn symlink(
        &mut self,
        link: impl AsRef<Path>,
        target: impl AsRef<Path>,
        mode: Mode,
    ) -> Result<&mut PackageBuilder, Error> {
        self.entries.push(
            BuilderEntry::new(
                target, mode,
                BuilderEntryKind::Symlink(link.as_ref().to_path_buf()),
            )?
        );
        Ok(self)
    }
    
    /// Add a file to this builder. `source` is a Reader to read the entry's
    /// data from.
    pub fn file_reader(
        &mut self,
        source: impl Read + 'static,
        target: impl AsRef<Path>,
        mode: Mode,
    ) -> Result<&mut PackageBuilder, Error> {
        self.entries.push(
            BuilderEntry::new(
                target, mode,
                BuilderEntryKind::Reader(Box::new(source)),
            )?
        );
        Ok(self)
    }
    
    /// Iterate a directory and replicate its relative structure in this
    /// builder by adding entries for all files and symlinks.
    pub fn dir(&mut self, dir: impl AsRef<Path>) -> Result<&mut PackageBuilder, Error> {
        let dir = dir.as_ref();
        self.add_dir_entries(&dir, &dir)
            .chain_err(|| format!("Failed to walk directory: {}", dir.display()) )?;
        Ok(self)
    }
    
    /// Recursive helper to walk directory and yield `BuilderEntry` to
    /// `self.entries`
    fn add_dir_entries(
        &mut self,
        base: &Path,
        current: &Path
    ) -> Result<(), Error> {
        let read_dir = fs::read_dir(current)
            .chain_err(|| current )?;
        
        for entry_result in read_dir{
            let entry = entry_result
                .chain_err(|| current )?;
            let path = entry.path();
            let metadata = entry.metadata()
                .chain_err(|| path.as_path() )?;
            let file_type = metadata.file_type();
            let file_mode = metadata.permissions()
                .mode();
            
            if file_type.is_dir() {
                self.add_dir_entries(base, &path)?;
            } else {
                let target = path.strip_prefix(base)
                    // This shouldn't be reachable
                    .expect(&format!(
                        "base ({}) was not found in path ({})",
                        base.display(), path.display()
                    ))
                    .to_path_buf();
                
                if file_type.is_file() {
                    self.entries.push(
                        BuilderEntry::new(
                            target,
                            Mode::from_bits_truncate(file_mode),
                            BuilderEntryKind::File(path)
                        )?);
                } else if file_type.is_symlink() {
                    self.entries.push(
                        BuilderEntry::new(
                            target,
                            Mode::from_bits_truncate(file_mode),
                            BuilderEntryKind::Symlink(
                                fs::read_link(&path)
                                    .chain_err(|| path.as_path() )?,
                            ),
                        )?);
                } else {
                    unreachable!();
                }
            }
        }
        Ok(())
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
    // Also don't call it before write_data has been called.
    // TODOS from jackpot51's implementation:
    // - fallocate data_offset + data_size
    // - ensure file size matches
    fn write_head<W>(&self, writer: &mut W) -> Result<u64, Error>
        where W: Write + Seek,
    {
        let secret_key = self.keys.key()
            .expect("PackageBuilder was passed encrypted keys");
        
        let mut hasher = Hasher::new();
        let mut offset = 0;
        
        writer.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
        
        for entry in self.entries.iter() {
            match entry.kind {
                BuilderEntryKind::Written(entry) => {
                    let entry_bytes = unsafe {
                        plain::as_bytes(&entry)
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
        ).to_bytes();
        
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(unsafe { plain::as_bytes(&header) })?;
        offset += HEADER_SIZE;
        
        Ok(offset as u64)
    }
    
    /// Assumes `writer` starts at position 0 when calculating offsets.
    /// Returns the total length of the data segment.
    //WARN: Don't call this when the user can get mutable access again
    fn write_data(&mut self, mut writer: &mut impl Write) -> Result<u64, Error> {
        // Sort the entires by target path (prevents collisions between file
        // names causing possible indeterminism).
        // This is done to make the build deterministic: the same inputs should
        // result in _exactly_ the same archive every time.
        self.entries.sort_by(|a, b| a.target.cmp(&b.target) );
        
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        let mut written = 0;
        
        for builder_entry in self.entries.iter_mut() {
            let (size, hash) = match &mut builder_entry.kind {
                BuilderEntryKind::File(source_path) => {
                    let source_file = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&source_path)
                        .chain_err(|| source_path.as_path() )?;
                    
                    copy_and_hash(source_file, &mut writer, &mut buf)
                        .chain_err(|| source_path.as_path() )?
                },
                BuilderEntryKind::Reader(source) => {
                    copy_and_hash(source, &mut writer, &mut buf)?
                },
                BuilderEntryKind::Symlink(link_contents) => {
                    let link_bytes = link_contents.as_os_str().as_bytes();
                    copy_and_hash(link_bytes, &mut writer, &mut buf)?
                },
                BuilderEntryKind::Written(_) => panic!("write_data shouldn't reach written"),
            };
            
            let entry = Entry::new(
                hash, written, size,
                builder_entry.mode, &builder_entry.target
            )?;
            // Non-relative paths are invalid
            entry.check_path()?;
            
            builder_entry.kind = BuilderEntryKind::Written(entry);
            written += size;
        }
        Ok(written)
    }
}

impl fmt::Debug for PackageBuilder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PackageBuilder")
            .field("entries", &self.entries)
            .finish()
    }
}

