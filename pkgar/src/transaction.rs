use std::io;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake3::Hash;
use pkgar_core::PackageSrc;

use crate::{Error, MODE_FILE, MODE_KIND, MODE_PERM, MODE_SYMLINK};
use crate::bin::copy_entry_and_hash;
use crate::ext::EntryExt;

/// Returns `None` if the target path has no parent (was `/`)
fn temp_path(target_path: impl AsRef<Path>, entry_hash: Hash) -> Option<PathBuf> {
    let tmp_name = if let Some(filename) = target_path.as_ref().file_name() {
        format!(".pkgar.{}", Path::new(filename).display())
    } else {
        format!(".pkgar.{}", entry_hash.to_hex())
    };
    target_path.as_ref().parent()
        .map(|parent| parent.join(tmp_name) )
}

enum Action {
    /// Temp files (`.pkgar.*`) to target files
    Rename(PathBuf, PathBuf),
    Remove(PathBuf),
}

impl Action {
    fn commit(&self) -> io::Result<()> {
        match self {
            Action::Rename(tmp, target) => fs::rename(tmp, target),
            Action::Remove(target) => fs::remove_file(target),
        }
    }
    
    fn abort(&self) -> io::Result<()> {
        match self {
            Action::Rename(tmp, _) => fs::remove_file(tmp),
            Action::Remove(_) => Ok(()),
        }
    }
}

pub struct Transaction {
    actions: Vec<Action>,
}

impl Transaction {
    pub fn new() -> Transaction {
        Transaction {
            actions: Vec::new(),
        }
    }
    
    pub fn install<Pkg, Pth>(&mut self, src: &mut Pkg, basedir: Pth) -> Result<(), Error>
    where
        Pkg: PackageSrc<Err = Error>,
        Pth: AsRef<Path>,
    {
        let mut buf = vec![0; 4 * 1024 * 1024];
        
        for entry in src.read_entries()? {
            let relative_path = entry.check_path()?;
            
            let target_path = basedir.as_ref().join(relative_path);
            //HELP: Under what circumstances could this ever fail?
            assert!(target_path.starts_with(&basedir), "target path was not in the base path");
            
            let entry_hash = Hash::from(entry.blake3());
            let tmp_path = temp_path(&target_path, entry_hash)
                .ok_or(Error::InvalidPath {
                    entry: PathBuf::from(relative_path),
                    component: PathBuf::from("/"),
                })?;

            let mode_kind = entry.mode() & MODE_KIND;
            let mode_perm = entry.mode() & MODE_PERM;
            let (entry_data_size, entry_data_hash) = match mode_kind {
                MODE_FILE => {
                    //TODO: decide what to do when temp files are left over
                    let mut tmp_file = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(mode_perm)
                        .open(&tmp_path)?;
                    copy_entry_and_hash(src, entry, &mut tmp_file, &mut buf)?
                },
                MODE_SYMLINK => {
                    let mut data = Vec::new();
                    let (size, hash) = copy_entry_and_hash(src, entry, &mut data, &mut buf)?;
                    let sym_target: &OsStr = OsStrExt::from_bytes(data.as_slice());
                    symlink(sym_target, &tmp_path)?;
                    (size, hash)
                },
                _ => {
                    return Err(Error::UnsupportedMode {
                        entry: PathBuf::from(relative_path),
                        mode: entry.mode(),
                    });
                }
            };
            
            if entry_data_size != entry.size() {
                Err(Error::LengthMismatch {
                    entry: PathBuf::from(relative_path),
                    actual: entry_data_size,
                    expected: entry.size(),
                })
            } else if entry_data_hash != entry_hash {
                Err(Error::Core(pkgar_core::Error::InvalidBlake3))
            } else { Ok(()) }?;
            
            self.actions.push(Action::Rename(tmp_path, target_path))
        }
        Ok(())
    }
    
    pub fn upgrade<Pkg, Pth>(&mut self, old: &mut Pkg, new: Pkg, basedir: Pth) -> Result<(), Error>
    where
        Pkg: PackageSrc<Err = Error>,
        Pth: AsRef<Path>,
    {
        unimplemented!();
    }
    
    pub fn remove<Pkg, Pth>(&mut self, pkg: &mut Pkg, basedir: Pth) -> Result<(), Error>
    where
        Pkg: PackageSrc<Err = Error>,
        Pth: AsRef<Path>,
    {
        unimplemented!();
    }
    
    pub fn commit(&mut self) -> Result<usize, Error> {
        let mut count = 0;
        while let Some(action) = self.actions.pop() {
            if let Err(err) = action.commit() {
                // Should be possible to restart a failed transaction
                self.actions.push(action);
                return Err(Error::FailedCommit {
                    changed: count,
                    remaining: self.actions.len(),
                    source: err,
                });
            }
            count += 1;
        }
        Ok(count)
    }
    
    /// Clean up any tmp files referenced by this transaction without committing.
    /// Note that this function will check all actions and only after it has attempted
    /// to abort them all will it return an error with context info. Remaining actions
    /// are left as a part of this transaction to allow for re-runs of this function.
    pub fn abort(&mut self) -> Result<usize, Error> {
        let mut count = 0;
        let mut last_failed = false;
        while let Some(action) = self.actions.pop() {
            if let Err(err) = action.abort() {
                // This is inherently inefficent, no biggie
                self.actions.insert(0, action);
                if last_failed {
                    //TODO: Somehow indicate that this is a failed abort instead of a commit
                    return Err(Error::FailedCommit {
                        changed: count,
                        remaining: self.actions.len(),
                        source: err,
                    });
                } else {
                    last_failed = true;
                }
            }
            count += 1;
        }
        Ok(count)
    }
}

