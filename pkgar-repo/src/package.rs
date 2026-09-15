use pkgar_core::{Header, PackageSrc, PublicKey, Zeroable};

use crate::{Error, reader::PackageUrlReader};

pub struct PackageUrl<'a> {
    client: &'a ureq::Agent,
    url: String,
    header: Header,
}

impl<'a> PackageUrl<'a> {
    pub fn new(
        client: &'a ureq::Agent,
        url: String,
        public_key: &PublicKey,
    ) -> Result<Self, Error> {
        let mut new = Self {
            client,
            url,
            // Need a blank header to construct the PackageFile, since we need to
            // use a method of PackageSrc in order to get the actual header...
            header: Header::zeroed(),
        };
        new.header = new.read_header(public_key)?;
        Ok(new)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn get_reader(&self) -> PackageUrlReader<'a> {
        PackageUrlReader::new(self.client, &self.url)
    }
}

impl PackageSrc for PackageUrl<'_> {
    type Err = Error;

    fn header(&self) -> Header {
        self.header
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        PackageUrlReader::new(self.client, &self.url).read_at(offset, buf)
    }
}
