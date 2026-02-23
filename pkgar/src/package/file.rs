use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use bytemuck::Zeroable;
use pkgar_core::{Header, PackageSrc, PublicKey};

use crate::ext::{copy_and_hash, DataReader, EntryExt, PackageSrcExt};
use crate::{wrap_io_err, Error, READ_WRITE_HASH_BUF_SIZE};

#[derive(Debug)]
pub struct PackageFile {
    path: PathBuf,
    src: Option<BufReader<File>>,
    header: Header,
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
            src: Some(BufReader::new(file)),

            // Need a blank header to construct the PackageFile, since we need to
            //   use a method of PackageSrc in order to get the actual header...
            header: Header::zeroed(),
        };

        new.header = new.read_header(public_key)?;
        Ok(new)
    }

    pub fn split(&mut self, head_path: &Path, data_path_opt: Option<&Path>) -> Result<(), Error> {
        let data_offset = self.header().total_size()? as u64;
        let mut src = self.take_reader()?;

        if let Some(data_path) = data_path_opt {
            let mut data_file =
                fs::File::create(data_path).map_err(wrap_io_err!(data_path, "Opening data"))?;
            src.seek(SeekFrom::Start(data_offset))
                .map_err(wrap_io_err!(data_path, "Seeking data"))?;
            std::io::copy(&mut src, &mut data_file)
                .map_err(wrap_io_err!(data_path, "Writing data"))?;
        }
        {
            let mut head_file =
                fs::File::create(head_path).map_err(wrap_io_err!(head_path, "Opening head"))?;
            src.seek(SeekFrom::Start(0))
                .map_err(wrap_io_err!(head_path, "Seeking head"))?;
            let mut src_taken = src.take(data_offset);
            std::io::copy(&mut src_taken, &mut head_file)
                .map_err(wrap_io_err!(head_path, "Writing head"))?;
            self.restore_reader(src_taken.into_inner())?;
        }

        Ok(())
    }

    pub fn verify(&mut self, base_dir: &Path) -> Result<(), Error> {
        let entries = self.read_entries()?;
        let mut pkg_file = self.take_reader()?;
        let header = self.header();

        let mut buf = vec![0; READ_WRITE_HASH_BUF_SIZE];
        for entry in entries {
            let expected_path = base_dir.join(entry.check_path()?);

            let mut expected =
                File::open(&expected_path).map_err(wrap_io_err!(expected_path, "Opening file"))?;

            let (count, hash) = copy_and_hash(&mut expected, &mut std::io::sink(), &mut buf)
                .map_err(wrap_io_err!(expected_path, "Writing file to to black hole"))?;

            let reader = DataReader::new_with_seek(&header, pkg_file, &entry)
                .map_err(wrap_io_err!(self.path, "Reading pkg data"))?;
            entry.verify(hash, count, &reader)?;
            pkg_file = reader.into_inner();
        }

        self.restore_reader(pkg_file)?;

        Ok(())
    }
}

impl PackageSrc for PackageFile {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let Some(src) = &mut self.src else {
            return Err(Error::DataNotInitialized);
        };
        src.seek(SeekFrom::Start(offset))
            .map_err(wrap_io_err!("Seek at read_at"))?;
        src.read_exact(buf)
            .map_err(wrap_io_err!("Read at read_at"))?;
        Ok(buf.len())
    }
}

impl PackageSrcExt<File> for PackageFile {
    fn path(&self) -> &Path {
        &self.path
    }

    fn take_reader(&mut self) -> Result<File, Error> {
        match self.src.take() {
            Some(reader) => Ok(reader.into_inner()),
            None => Err(Error::DataNotInitialized),
        }
    }

    fn restore_reader(&mut self, reader: File) -> Result<(), Error> {
        match self.src {
            Some(_) => Err(Error::Core(pkgar_core::Error::NotSupported)),
            ref mut src => {
                *src = Some(BufReader::new(reader));
                Ok(())
            }
        }
    }
}
