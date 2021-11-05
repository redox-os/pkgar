use std::io;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake3::Hash;

use crate::{
    copy_and_hash,
    core::{Mode, PackageData, PackageHead},
    EntryExt,
    Error,
    ErrorKind,
    READ_WRITE_HASH_BUF_SIZE,
    ResultExt,
    PackageDataExt,
};

fn file_exists(path: impl AsRef<Path>) -> Result<bool, Error> {
    if let Err(err) = fs::metadata(&path) {
        if err.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(Error::from(err)
                .chain_err(|| path.as_ref() ))
        }
    } else {
        Ok(true)
    }
}

/// Determine the temporary path for a file, and create its parent directories.
/// Returns `Err` if the target path has no parent (was `/`).
fn temp_path(target_path: impl AsRef<Path>, entry_hash: Hash) -> Result<PathBuf, Error> {
    let target_path = target_path.as_ref();
    let hash_path = format!(".pkgar.{}", entry_hash.to_hex());
    
    let tmp_name = if let Some(filename) = target_path.file_name() {
        let name_path = format!(".pkgar.{}", Path::new(filename).display());
        
        if file_exists(&name_path)? {
            eprintln!("warn: temporary path already exists at {}", name_path);
            hash_path
        } else {
            name_path
        }
    } else {
        // It's fine to not check the existence of this file, since if the a
        //   file with the same hash already exists, we know what its
        //   contents should be.
        hash_path
    };
    
    let parent_dir = target_path.parent()
        .ok_or(ErrorKind::InvalidPathComponent(PathBuf::from("/")))?;
    fs::create_dir_all(parent_dir)
        .chain_err(|| parent_dir )?;
    Ok(parent_dir.join(tmp_name))
}

enum Action {
    /// Temp files (`.pkgar.*`) to target files
    Rename(PathBuf, PathBuf),
    Remove(PathBuf),
}

impl Action {
    fn commit(&self) -> Result<(), Error> {
        match self {
            Action::Rename(tmp, target) => fs::rename(&tmp, target)
                .chain_err(|| tmp ),
            Action::Remove(target) => fs::remove_file(&target)
                .chain_err(|| target ),
        }
    }
    
    fn abort(&self) -> Result<(), Error> {
        match self {
            Action::Rename(tmp, _) => fs::remove_file(&tmp)
                .chain_err(|| tmp ),
            Action::Remove(_) => Ok(()),
        }
    }
}

/// Extraction options for individual packages.
///
/// A `Transaction` is a handle to some temporary files on the system. The
/// constructors of this type create the tempfiles and [`Transaction::commit`]
/// moves them into their destination name, thus replacing a package with
/// another package is almost atomic.
///
/// Temp files are named according to their containing directory and filename,
/// or containing directory and hash, if the temp file name already exists.
/// Thus, the temp file for a package entry targeted to `etc/fun/other.toml`
/// unpacking at a base path of `/` will be located at
/// `/etc/fun/.pkgar.other.toml` or `/etc/fun/.pkgar.<entry_hash>` if the
/// former path already exists.
///
/// ## A word on types
/// The constructors of `Transaction` take parameters that either
/// `impl PackageHead`, or are `Pkg: PackageHead + PackageData`. In order to
/// use types that only implement one of these traits, they are implemented
/// for 2-tuples that contain both types (see [`PackageHead`] and
/// [`PackageData`]), so that this syntax works:
/// ```no_run
/// use pkgar::{PackageFile, Transaction};
/// use pkgar::keys::PublicKeyFile;
///
/// let pkey = PublicKeyFile::open("/pkg/keys/somekey.pub.toml")
///     .unwrap()
///     .pkey;
/// let head = PackageFile::open_head("my_pkg.pkgar_head", &pkey).unwrap();
/// let data = PackageFile::open_data("my_pkg.pkgar_data").unwrap();
///
/// Transaction::install(&(head, data), "/base/path")
///     .unwrap()
///     .commit()
///     .unwrap();
/// ```
pub struct Transaction {
    actions: Vec<Action>,
}

impl Transaction {
    pub fn install<Pkg>(
        pkg: &Pkg,
        base_dir: impl AsRef<Path>,
    ) -> Result<Transaction, Error>
        where Pkg: PackageHead + PackageData<Err = Error> + PackageDataExt,
    {
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        
        let mut actions = Vec::with_capacity(pkg.header().count() as usize);
        
        for entry in pkg.entries().cloned() {
            //TODO: Path context for invalid entry data
            let relative_path = entry.check_path()
                .chain_err(|| entry )?;
            
            let target_path = base_dir.as_ref().join(relative_path);
            //HELP: Under what circumstances could this ever fail?
            assert!(target_path.starts_with(&base_dir),
                "target path was not in the base path");
            
            let tmp_path = temp_path(&target_path, entry.blake3())?;
            
            let mode = entry.mode()
                .map_err(Error::from)
                .chain_err(|| entry )?;
            
            let mut entry_reader = pkg.entry_reader(entry);
            
            match mode.kind() {
                Mode::FILE => {
                    //TODO: decide what to do when temp files are left over
                    let mut tmp_file = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(mode.perm().bits())
                        .open(&tmp_path)
                        .chain_err(|| tmp_path.as_path() )?;
                    
                    entry_reader.copy(&mut tmp_file, &mut buf)
                        .chain_err(|| &tmp_path )
                        .chain_err(|| format!("Copying entry to tempfile: '{}'", relative_path.display()) )?;
                },
                Mode::SYMLINK => {
                    let mut sym_target_bytes = Vec::new();
                    entry_reader.copy(&mut sym_target_bytes, &mut buf)
                        .chain_err(|| &tmp_path )
                        .chain_err(|| format!("Copying entry to tempfile: '{}'", relative_path.display()) )?;
                    
                    let sym_target = Path::new(OsStr::from_bytes(&sym_target_bytes));
                    symlink(sym_target, &tmp_path)
                        .chain_err(|| sym_target )
                        .chain_err(|| format!("Symlinking to {}", tmp_path.display()) )?;
                },
                _ => {
                    return Err(Error::from(
                            pkgar_core::Error::InvalidMode(mode.bits())
                        ))
                        .chain_err(|| entry );
                }
            };
            
            entry_reader.verify()
                .chain_err(|| pkg.path() )?;
            
            actions.push(Action::Rename(tmp_path, target_path))
        }
        Ok(Transaction {
            actions,
        })
    }
    
    pub fn replace<Pkg>(
        old: &impl PackageHead,
        new: &Pkg,
        base_dir: impl AsRef<Path>,
    ) -> Result<Transaction, Error>
        where Pkg: PackageHead + PackageData<Err = Error> + PackageDataExt,
    {
        // All the files that are present in old but not in new
        let mut actions = old.entries()
            .filter(|old_e| new.entries()
                .find(|new_e| new_e.blake3() == old_e.blake3() )
                .is_none())
            .map(|e| {
                let target_path = base_dir.as_ref()
                    .join(e.check_path()?);
                Ok(Action::Remove(target_path))
            })
            .collect::<Result<Vec<Action>, Error>>()?;
        
        let mut trans = Transaction::install(new, base_dir)?;
        trans.actions.append(&mut actions);
        Ok(trans)
    }
    
    pub fn remove(
        pkg: &impl PackageHead,
        base_dir: impl AsRef<Path>,
    ) -> Result<Transaction, Error> {
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        
        let mut actions = Vec::with_capacity(pkg.header().count() as usize);
        
        for entry in pkg.entries() {
            let relative_path = entry.check_path()?;
            
            let target_path = base_dir.as_ref()
                .join(relative_path);
            // Under what circumstances could this ever fail?
            assert!(target_path.starts_with(&base_dir),
                "target path was not in the base path");
            
            let candidate = File::open(&target_path)
                .chain_err(|| &target_path )?;
            
            // Ensure that the deletion candidate on disk has not been modified
            copy_and_hash(candidate, io::sink(), &mut buf)
                .chain_err(|| &target_path )
                .chain_err(|| format!("Hashing file for entry: '{}'", relative_path.display()) )?;
            
            actions.push(Action::Remove(target_path));
        }
        Ok(Transaction {
            actions
        })
    }
    
    pub fn commit(&mut self) -> Result<usize, Error> {
        let mut count = 0;
        while let Some(action) = self.actions.pop() {
            if let Err(err) = action.commit() {
                // Should be possible to restart a failed transaction
                self.actions.push(action);
                return Err(err
                    .chain_err(|| ErrorKind::FailedCommit(count, self.actions.len()) )
                );
            }
            count += 1;
        }
        Ok(count)
    }
    
    /// Clean up any temp files referenced by this transaction without committing.
    /// Note that this function will check all temp files and only after it has
    /// attempted to remove them all will it return an error with context info.
    /// Failed removes are left as a part of this transaction to allow for
    /// re-runs of this function.
    pub fn abort(&mut self) -> Result<usize, Error> {
        let mut count = 0;
        let mut last_failed = false;
        while let Some(action) = self.actions.pop() {
            if let Err(err) = action.abort() {
                // This is inherently inefficent, no biggie
                self.actions.insert(0, action);
                if last_failed {
                    return Err(err
                        .chain_err(|| ErrorKind::FailedCommit(count, self.actions.len()) )
                        .chain_err(|| "Abort triggered" )
                    );
                } else {
                    last_failed = true;
                }
            }
            count += 1;
        }
        Ok(count)
    }
}

