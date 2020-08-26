use std::io;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake3::Hash;
use pkgar_core::{Mode, PackageSrc};

use crate::{Error, ErrorKind};
use crate::ext::{copy_and_hash, EntryExt, PackageSrcExt};

const READ_WRITE_HASH_BUF_SIZE: usize = 4 * 1024 * 1024;

/// Returns `None` if the target path has no parent (was `/`)
fn temp_path(target_path: impl AsRef<Path>, entry_hash: Hash) -> Result<PathBuf, Error> {
    let tmp_name = if let Some(filename) = target_path.as_ref().file_name() {
        format!(".pkgar.{}", Path::new(filename).display())
    } else {
        format!(".pkgar.{}", entry_hash.to_hex())
    };
    
    let parent = target_path.as_ref().parent()
        .ok_or(ErrorKind::InvalidPathComponent(PathBuf::from("/")))?;
    fs::create_dir_all(&parent)
        .map_err(|e| Error::from(e).path(parent) )?;
    Ok(parent.join(tmp_name))
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
    pub fn install<Pkg>(
        src: &mut Pkg,
        base_dir: impl AsRef<Path>
    ) -> Result<Transaction, Error>
        where Pkg: PackageSrc<Err = Error> + PackageSrcExt,
    {
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        
        let entries = src.read_entries()?;
        let mut actions = Vec::with_capacity(entries.len());
        
        for entry in entries {
            let relative_path = entry.check_path()
                .map_err(|e| e.path(src.path()) )?;
            
            let target_path = base_dir.as_ref().join(relative_path);
            //HELP: Under what circumstances could this ever fail?
            assert!(target_path.starts_with(&base_dir),
                "target path was not in the base path");
            
            let tmp_path = temp_path(&target_path, entry.blake3())?;
            
            let mode = entry.mode()
                .map_err(|e| Error::from(e)
                    .path(src.path())
                    .entry(entry)
                )?;
            
            let (entry_data_size, entry_data_hash) = match mode.kind() {
                Mode::FILE => {
                    //TODO: decide what to do when temp files are left over
                    let mut tmp_file = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(mode.perm().bits())
                        .open(&tmp_path)
                        .map_err(|e| Error::from(e).path(&tmp_path) )?;
                    
                    copy_and_hash(src.entry_reader(entry), &mut tmp_file, &mut buf)
                        .map_err(|e| Error::from(e)
                            .reason(format!("Copying entry to tempfile: '{}'", relative_path.display()))
                            .path(&tmp_path)
                        )?
                },
                Mode::SYMLINK => {
                    let mut data = Vec::new();
                    let (size, hash) = copy_and_hash(src.entry_reader(entry), &mut data, &mut buf)
                        .map_err(|e| Error::from(e)
                            .reason(format!("Copying entry to tempfile: '{}'", relative_path.display()))
                            .path(&tmp_path)
                        )?;
                    let sym_target: &OsStr = OsStrExt::from_bytes(data.as_slice());
                    symlink(sym_target, &tmp_path)
                        .map_err(|e| Error::from(e)
                            .reason(format!("Symlinking to {}", tmp_path.display()))
                            .path(&sym_target)
                        )?;
                    (size, hash)
                },
                _ => {
                    return Err(Error::from(
                            pkgar_core::Error::InvalidMode(mode.bits())
                        )
                        .entry(entry)
                        .path(src.path()));
                }
            };
            
            entry.verify(entry_data_hash, entry_data_size)
                .map_err(|e| e.path(src.path()))?;
            
            actions.push(Action::Rename(tmp_path, target_path))
        }
        Ok(Transaction {
            actions,
        })
    }
    
    pub fn replace<Pkg>(
        old: &mut Pkg,
        new: &mut Pkg,
        base_dir: impl AsRef<Path>,
    ) -> Result<Transaction, Error>
        where Pkg: PackageSrc<Err = Error> + PackageSrcExt,
    {
        let old_entries = old.read_entries()?;
        let new_entries = new.read_entries()?;
        
        // All the files that are present in old but not in new
        let mut actions = old_entries.iter()
            .filter(|old_e| new_entries.iter()
                .find(|new_e| new_e.blake3() == old_e.blake3() )
                .is_none())
            .map(|e| {
                let target_path = base_dir.as_ref()
                    .join(e.check_path()?);
                Ok(Action::Remove(target_path))
            })
            .collect::<Result<Vec<Action>, Error>>()?;
        
        //TODO: Don't force a re-read of all the entries for the new package
        let mut trans = Transaction::install(new, base_dir)?;
        trans.actions.append(&mut actions);
        Ok(trans)
    }
    
    pub fn remove<Pkg>(
        pkg: &mut Pkg,
        base_dir: impl AsRef<Path>
    ) -> Result<Transaction, Error>
        where Pkg: PackageSrc<Err = Error>,
    {
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        
        let entries = pkg.read_entries()?;
        let mut actions = Vec::with_capacity(entries.len());
        
        for entry in entries {
            let relative_path = entry.check_path()?;
            
            let target_path = base_dir.as_ref()
                .join(relative_path);
            // Under what circumstances could this ever fail?
            assert!(target_path.starts_with(&base_dir),
                "target path was not in the base path");
            
            let candidate = File::open(&target_path)
                .map_err(|e| Error::from(e).path(&target_path) )?;
            
            // Ensure that the deletion candidate on disk has not been modified
            copy_and_hash(candidate, io::sink(), &mut buf)
                .map_err(|e| Error::from(e)
                    .reason(format!("Hashing file for entry: '{}'", relative_path.display()))
                    .path(&target_path)
                )?;
            
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
                return Err(ErrorKind::FailedCommit {
                    changed: count,
                    remaining: self.actions.len(),
                    source: err,
                }.into());  //TODO: Add path context to this error
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
                    //TODO: Add path context to this error
                    return Err(ErrorKind::FailedCommit {
                        changed: count,
                        remaining: self.actions.len(),
                        source: err,
                    }.into());
                } else {
                    last_failed = true;
                }
            }
            count += 1;
        }
        Ok(count)
    }
}

