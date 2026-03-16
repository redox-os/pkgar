use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake3::Hash;
use pkgar_core::{Mode, PackageSrc};

use crate::ext::{copy_and_hash, EntryExt, PackageSrcExt};
use crate::{wrap_io_err, Error, READ_WRITE_HASH_BUF_SIZE};

fn file_exists(path: impl AsRef<Path>) -> Result<bool, Error> {
    let path = path.as_ref();
    if let Err(err) = fs::symlink_metadata(path) {
        if err.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(Error::Io {
                source: err,
                path: Some(path.to_path_buf()),
                context: "Checking file",
            })
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
    let parent_dir = target_path
        .parent()
        .ok_or_else(|| Error::InvalidPathComponent {
            invalid: PathBuf::from("/"),
            path: target_path.to_path_buf(),
            entry: None,
        })?;

    let tmp_name = if let Some(filename) = target_path.file_name() {
        let name_path = format!(".pkgar.{}", Path::new(filename).display());

        if file_exists(parent_dir.join(&name_path))? {
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

    fs::create_dir_all(parent_dir)
        .map_err(wrap_io_err!(parent_dir.to_path_buf(), "Creating dir"))?;
    Ok(parent_dir.join(tmp_name))
}

/// Individual atomic file operation
#[derive(Clone, Debug)]
pub enum Action {
    /// Temp files (`.pkgar.*`) to target files
    Rename(PathBuf, PathBuf),
    Remove(PathBuf),
}

impl Action {
    fn commit(&self) -> Result<(), Error> {
        match self {
            Action::Rename(tmp, target) => {
                fs::rename(tmp, target).map_err(wrap_io_err!(tmp.to_path_buf(), "Renaming file"))
            }
            Action::Remove(target) => {
                fs::remove_file(target).map_err(wrap_io_err!(target.to_path_buf(), "Removing file"))
            }
        }
    }

    fn abort(&self) -> Result<(), Error> {
        match self {
            Action::Rename(tmp, _) => {
                fs::remove_file(tmp).map_err(wrap_io_err!(tmp.to_path_buf(), "Removing tempfile"))
            }
            Action::Remove(_) => Ok(()),
        }
    }

    /// Returns the file path it's targeting into
    pub fn target_file(&self) -> &Path {
        match self {
            Action::Rename(_, path) => path.as_path(),
            Action::Remove(path) => path.as_path(),
        }
    }
}

/// A struct that holds many atomic file operation
pub struct Transaction {
    actions: Vec<Action>,
    committed: usize,
}

impl Transaction {
    fn new(actions: Vec<Action>) -> Self {
        Self {
            actions,
            committed: 0,
        }
    }

    /// Prepare transactions to install from a pkgar file
    pub fn install<Pkg>(src: &mut Pkg, base_dir: impl AsRef<Path>) -> Result<Self, Error>
    where
        Pkg: PackageSrc<Err = Error> + PackageSrcExt<File>,
    {
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];

        let entries = src.read_entries()?;
        let mut actions = Vec::with_capacity(entries.len());

        for entry in entries {
            let relative_path = entry.check_path()?;

            let target_path = base_dir.as_ref().join(relative_path);
            //HELP: Under what circumstances could this ever fail?
            assert!(
                target_path.starts_with(&base_dir),
                "target path was not in the base path"
            );

            let tmp_path = temp_path(&target_path, entry.blake3())?;

            let mode = entry.mode().map_err(Error::from)?;
            let mut data_reader = src.data_reader(entry)?;

            let (entry_data_size, entry_data_hash) = match mode.kind() {
                Mode::FILE => {
                    // Tempfiles will be overwritten, users should use MergedTransaction to handle transaction conflicts
                    let mut tmp_file = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(mode.perm().bits())
                        .open(&tmp_path)
                        .map_err(wrap_io_err!(tmp_path, "Opening tempfile"))?;

                    let (size, hash) = copy_and_hash(&mut data_reader, &mut tmp_file, &mut buf)
                        .map_err(wrap_io_err!(tmp_path, "Copying entry to tempfile"))?;

                    actions.push(Action::Rename(tmp_path, target_path));
                    (size, hash)
                }
                Mode::SYMLINK => {
                    let mut data = Vec::new();
                    let (size, hash) = copy_and_hash(&mut data_reader, &mut data, &mut buf)
                        .map_err(wrap_io_err!(tmp_path, "Copying entry to tempfile"))?;

                    let sym_target = Path::new(OsStr::from_bytes(&data));
                    symlink(sym_target, &tmp_path)
                        .map_err(wrap_io_err!(tmp_path, "Symlinking to tmp"))?;
                    actions.push(Action::Rename(tmp_path, target_path));
                    (size, hash)
                }
                _ => {
                    return Err(Error::from(pkgar_core::Error::InvalidMode(mode.bits())));
                }
            };

            entry.verify(entry_data_hash, entry_data_size, &data_reader)?;
            data_reader.finish(src)?;
        }
        Ok(Transaction::new(actions))
    }

    /// Prepare transactions to replace old files from a pkgar file
    pub fn replace<Pkg>(
        old: &mut Pkg,
        new: &mut Pkg,
        base_dir: impl AsRef<Path>,
    ) -> Result<Transaction, Error>
    where
        Pkg: PackageSrc<Err = Error> + PackageSrcExt<File>,
    {
        let old_entries = old.read_entries()?;
        let new_entries = new.read_entries()?;

        // All the files that are present in old but not in new
        let mut actions = old_entries
            .iter()
            .filter(|old_e| {
                !new_entries
                    .iter()
                    .any(|new_e| new_e.blake3() == old_e.blake3())
            })
            .map(|e| {
                let target_path = base_dir.as_ref().join(e.check_path()?);
                Ok(Action::Remove(target_path))
            })
            .collect::<Result<Vec<Action>, Error>>()?;

        //TODO: Don't force a re-read of all the entries for the new package
        let mut trans = Transaction::install(new, base_dir)?;
        trans.actions.append(&mut actions);
        Ok(trans)
    }

    /// Prepare transactions to remove files from a pkgar file
    pub fn remove<Pkg>(pkg: &mut Pkg, base_dir: impl AsRef<Path>) -> Result<Transaction, Error>
    where
        Pkg: PackageSrc<Err = Error>,
    {
        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];

        let entries = pkg.read_entries()?;
        let mut actions = Vec::with_capacity(entries.len());

        for entry in entries {
            let relative_path = entry.check_path()?;

            let target_path = base_dir.as_ref().join(relative_path);
            // Under what circumstances could this ever fail?
            assert!(
                target_path.starts_with(&base_dir),
                "target path was not in the base path"
            );

            let mut candidate = File::open(&target_path)
                .map_err(wrap_io_err!(target_path.clone(), "Opening candidate"))?;

            // Ensure that the deletion candidate on disk has not been modified
            copy_and_hash(&mut candidate, &mut io::sink(), &mut buf)
                .map_err(wrap_io_err!(target_path.clone(), "Hashing file for entry"))?;

            actions.push(Action::Remove(target_path));
        }
        Ok(Transaction::new(actions))
    }

    /// Apply all pending actions from end to start.
    /// This resets the committed counter back to zero.
    /// if failed abort() is needed to clean up pending transaction.
    pub fn commit(&mut self) -> Result<usize, Error> {
        self.reset_committed();
        while self.actions.len() > 0 {
            self.commit_one()?;
        }
        Ok(self.committed)
    }

    /// Apply one last item from actions stack,
    /// returns how many transactions committed since last counter reset.
    pub fn commit_one(&mut self) -> Result<usize, Error> {
        if let Some(action) = self.actions.pop() {
            if let Err(err) = action.commit() {
                // Should be possible to restart a failed transaction
                self.actions.push(action);
                return Err(Error::FailedCommit {
                    source: Box::new(err),
                    changed: self.committed,
                    remaining: self.actions.len(),
                });
            }
            self.committed += 1;
        }
        Ok(self.committed)
    }

    /// Clean up any tmp files referenced by this transaction without committing.
    /// Note that this function will check all actions and only after it has attempted
    /// to abort them all will it return an error with context info. Remaining actions
    /// are left as a part of this transaction to allow for re-runs of this function.
    pub fn abort(&mut self) -> Result<usize, Error> {
        let mut last_failed = false;
        self.reset_committed();
        while self.actions.len() > 0 {
            if let Err(err) = self.abort_one() {
                if last_failed {
                    return Err(err);
                } else {
                    last_failed = true;
                }
            }
        }
        Ok(self.committed)
    }

    /// Abort one last item from actions stack
    pub fn abort_one(&mut self) -> Result<usize, Error> {
        if let Some(action) = self.actions.pop() {
            if let Err(err) = action.abort() {
                // This is inherently inefficent, no biggie
                self.actions.insert(0, action);
                return Err(Error::FailedCommit {
                    source: Box::new(err),
                    changed: self.committed,
                    remaining: self.actions.len(),
                });
            }
            self.committed += 1;
        }
        Ok(self.committed)
    }

    /// Get how much actions are pending
    pub fn pending_commit(&self) -> usize {
        self.actions.len()
    }

    /// Get how much actions committed.
    /// Aborted actions also counts.
    pub fn total_committed(&self) -> usize {
        self.committed
    }

    /// Resets committed counter
    pub fn reset_committed(&mut self) {
        self.committed = 0;
    }

    /// Peek pending actions.
    /// Actions are executed from last item.
    pub fn get_actions(&self) -> &Vec<Action> {
        &self.actions
    }
}

/// A struct that helps merging multiple transaction into one.
/// All transactions are validated to make sure there's no two action holding the same target file.
pub struct MergedTransaction {
    actions: Vec<Action>,
    path_map: BTreeMap<PathBuf, Option<String>>,
    possible_conflicts: Vec<TransactionConflict>,
}

impl MergedTransaction {
    pub fn new() -> Self {
        MergedTransaction {
            actions: Vec::new(),
            path_map: BTreeMap::new(),
            possible_conflicts: Vec::new(),
        }
    }
    fn push_action<Pkg>(&mut self, action: Action, src: Option<&Pkg>)
    where
        Pkg: PackageSrc<Err = Error> + PackageSrcExt<File>,
    {
        let action_key = action.target_file();
        match self.path_map.entry(action_key.to_path_buf()) {
            std::collections::btree_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(src.map(|s| s.path().to_string()));
                self.actions.push(action);
            }
            std::collections::btree_map::Entry::Occupied(occupied_entry) => {
                // When conflicts happened, it's assumed to be overwritten
                // However the order doesn't matter, so actions is not touched
                self.possible_conflicts.push(TransactionConflict {
                    conflicted_path: action_key.to_path_buf(),
                    former_src: occupied_entry.get().clone(),
                    newer_src: src.map(|s| s.path().to_string()),
                });
            }
        }
    }

    /// Add a newer transaction with their source package for optional conflict identification
    pub fn merge<Pkg>(&mut self, newer: Transaction, src: Option<&Pkg>)
    where
        Pkg: PackageSrc<Err = Error> + PackageSrcExt<File>,
    {
        for action in newer.actions {
            self.push_action(action, src);
        }
    }

    /// Get list of conflicted actions and their sources if given.
    /// The action that is actually used will be the newer one.
    pub fn get_possible_conflicts(&self) -> &Vec<TransactionConflict> {
        &self.possible_conflicts
    }

    /// Peek into held actions
    pub fn get_actions(&self) -> &Vec<Action> {
        &self.actions
    }

    /// Convert into single giant transaction
    pub fn into_transaction(self) -> Transaction {
        Transaction::new(self.actions)
    }
}

pub struct TransactionConflict {
    pub conflicted_path: PathBuf,
    pub former_src: Option<String>,
    pub newer_src: Option<String>,
}
