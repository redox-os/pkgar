use std::io;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake3::Hash;
use pkgar_core::{Mode, PackageSrc};

use crate::{Error, ErrorKind, READ_WRITE_HASH_BUF_SIZE, ResultExt};
use crate::ext::{copy_and_hash, EntryExt, PackageSrcExt};

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
                .chain_err(|| src.path() )?;
            
            let target_path = base_dir.as_ref().join(relative_path);
            //HELP: Under what circumstances could this ever fail?
            assert!(target_path.starts_with(&base_dir),
                "target path was not in the base path");
            
            let tmp_path = temp_path(&target_path, entry.blake3())?;
            
            let mode = entry.mode()
                .map_err(Error::from)
                .chain_err(|| src.path() )
                .chain_err(|| ErrorKind::Entry(entry) )?;
            
            let (entry_data_size, entry_data_hash) = match mode.kind() {
                Mode::FILE => {
                    //TODO: decide what to do when temp files are left over
                    let mut tmp_file = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(mode.perm().bits())
                        .open(&tmp_path)
                        .chain_err(|| tmp_path.as_path() )?;
                    
                    copy_and_hash(src.entry_reader(entry), &mut tmp_file, &mut buf)
                        .chain_err(|| &tmp_path )
                        .chain_err(|| format!("Copying entry to tempfile: '{}'", relative_path.display()) )?
                },
                Mode::SYMLINK => {
                    let mut data = Vec::new();
                    let (size, hash) = copy_and_hash(src.entry_reader(entry), &mut data, &mut buf)
                        .chain_err(|| &tmp_path )
                        .chain_err(|| format!("Copying entry to tempfile: '{}'", relative_path.display()) )?;
                    
                    let sym_target = Path::new(OsStr::from_bytes(&data));
                    symlink(sym_target, &tmp_path)
                        .chain_err(|| sym_target )
                        .chain_err(|| format!("Symlinking to {}", tmp_path.display()) )?;
                    (size, hash)
                },
                _ => {
                    return Err(Error::from(
                            pkgar_core::Error::InvalidMode(mode.bits())
                        ))
                        .chain_err(|| ErrorKind::Entry(entry) )
                        .chain_err(|| src.path() );
                }
            };
            
            entry.verify(entry_data_hash, entry_data_size)
                .chain_err(|| src.path() )?;
            
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

