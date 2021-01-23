use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::slice::Iter;

use sodiumoxide::crypto::sign::PublicKey;
use pkgar_core::{Entry, Header, HEADER_SIZE, PackageData, PackageHead, segment};

use crate::{Error, ErrorKind, ResultExt};
use crate::ext::PackageDataExt;

/// A `.pkgar` (or `.pkgar_head` or `.pkgar_data`) file on disk.
#[derive(Debug)]
pub struct PackageFile<S> {
    path: PathBuf,
    file: File,
    
    header: Option<Header>,
    entries: Vec<Entry>,
    
    _marker: PhantomData<S>,
}

impl<S: segment::HeadSeg> PackageFile<S> {
    fn open_with_head(
        path: impl AsRef<Path>,
        public_key: &PublicKey
    ) -> Result<PackageFile<S>, Error> {
        let path = path.as_ref().to_path_buf();
        
        let mut file = File::open(&path)
            .chain_err(|| &path )?;
        
        let mut header_bytes = [0; HEADER_SIZE];
        let count = file.read(&mut header_bytes[..])
            .chain_err(|| &path )?;

        if count != HEADER_SIZE {
            return Err(ErrorKind::PackageHeadTooShort)
                .map_err(Error::from)
                .chain_err(|| &path );
        }

        let header = *Header::new(&header_bytes[..], public_key)
            .map_err(Error::from)
            .chain_err(|| &path )?;

        let entries_size = header.entries_size()
            .map_err(Error::from)
            .chain_err(|| &path )? as usize;
        let mut entries_bytes = vec![0; entries_size];
        let count = file.read(&mut entries_bytes)
            .chain_err(|| &path )?;

        if count != entries_size {
            return Err(ErrorKind::PackageHeadTooShort)
                .map_err(Error::from)
                .chain_err(|| &path );
        }

        Ok(PackageFile {
            path,
            file,
            
            header: Some(header),
            entries: header.entries(&entries_bytes)?.to_vec(),
            
            _marker: PhantomData,
        })
    }
}

// See pkgar-core/src/package.rs for more on these
impl PackageFile<segment::Both> {
    /// Open a `.pkgar` file. The returned type implements both [`PackageHead`]
    /// and [`PackageData`].
    #[inline]
    pub fn open(
        path: impl AsRef<Path>,
        pkey: &PublicKey,
    ) -> Result<PackageFile<segment::Both>, Error> {
        PackageFile::open_with_head(path, pkey)
    }
}

impl PackageFile<segment::Head> {
    /// Open a `.pkgar_head` file. The returned type implements
    /// [`PackageHead`].
    #[inline]
    pub fn open_head(
        path: impl AsRef<Path>,
        pkey: &PublicKey,
    ) -> Result<PackageFile<segment::Head>, Error> {
        PackageFile::open_with_head(path, pkey)
    }
}

impl PackageFile<segment::Data> {
    /// Open a `.pkgar_data` file. The returned type implements
    /// [`PackageData`].
    pub fn open_data(
        path: impl AsRef<Path>
    ) -> Result<PackageFile<segment::Data>, Error> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)
            .chain_err(|| &path )?;
        Ok(PackageFile {
            path,
            file,
            
            header: None,
            entries: vec![],
            
            _marker: PhantomData,
        })
    }
}

impl<S: segment::HeadSeg> PackageHead for PackageFile<S> {
    fn header(&self) -> Header {
        self.header
            .expect("Package file with HeadSeg always has Some(header)")
    }

    fn entries(&self) -> Iter<'_, Entry> {
        self.entries.iter()
    }
}

impl<S: segment::DataSeg> PackageData for PackageFile<S> {
    type Err = Error;
    
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let offset = self.header.map(|h| h.total_size() )
            .transpose()?
            .unwrap_or(0) + offset;
        
        // Nevermind how this works...
        // https://stackoverflow.com/questions/31503488/why-is-it-possible-to-implement-read-on-an-immutable-reference-to-file
        (&self.file).seek(SeekFrom::Start(offset))
            .chain_err(|| &self.path )?;
        Ok((&self.file).read(buf)
           .chain_err(|| &self.path )?)
    }
}

impl<S: segment::DataSeg> PackageDataExt for PackageFile<S> {
    fn path(&self) -> &Path {
        &self.path
    }
}

