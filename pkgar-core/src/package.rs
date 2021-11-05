use core::convert::TryFrom;
use core::marker::PhantomData;
use core::slice::Iter;

use sodiumoxide::crypto::sign::PublicKey;

use crate::{Entry, Error, HEADER_SIZE, Header};

/// The head segment of an archive.
pub trait PackageHead {
    fn header(&self) -> Header;
    
    /// Returns an iterator of the entries in this `PackageHead`.
    fn entries(&self) -> Iter<'_, Entry>;
}

/// The data segment of an archive.
///
/// Users of types implementing this trait should usually use `read_entry` for
/// better bounds checking.
pub trait PackageData {
    type Err: From<Error>;
    
    /// Fill `buf` from the given `offset` within the data segment.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err>;
    
    /// Fill `buf` from a given entry's data + `offset` within that entry.
    fn read_entry(
        &self,
        entry: Entry,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize, Self::Err> {
        if offset as u64 > entry.size {
            return Ok(0);
        }
        
        let mut end = usize::try_from(entry.size - offset as u64)
            .map_err(Error::TryFromInt)?;
        
        if end > buf.len() {
            end = buf.len();
        }
        
        let offset = entry.offset + offset as u64;
        
        self.read_at(offset as u64, &mut buf[..end])
    }
}

/// Allow a tuple of `(PackageHead, PackageData)` to implement both traits, so
/// as to allow other APIs to take only one entity.
impl<H: PackageHead, A> PackageHead for (H, A) {
    #[inline]
    fn header(&self) -> Header {
        self.0.header()
    }

    #[inline]
    fn entries(&self) -> Iter<'_, Entry> {
        self.0.entries()
    }
}

/// Allow a tuple of `(PackageHead, PackageData)` to implement both traits, so
/// as to allow other APIs to take only one entity.
impl<A, D: PackageData> PackageData for (A, D) {
    type Err = D::Err;

    #[inline]
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Err> {
        self.1.read_at(offset, buf)
    }
}

/// Marker types for package sources. Most users of the API will not directly
/// interact with these.
///
/// These types are used for conditional compilation to allow for a more robust
/// API. See [`PackageBuf`] for an example of their use.
pub mod segment {
    /// Indicates that a type (one of the marker types in this module)
    /// represents the head segment of a pkgar.
    pub trait HeadSeg {}
    /// Indicates that a type (one of the marker types in this module)
    /// represents the data segment of a pkgar.
    pub trait DataSeg {}
    
    /// Marker indicating that the Head segment is provided by the enclosing
    /// type.
    pub struct Head;
    impl HeadSeg for Head {}
    
    /// Marker indicating that the Data segment is provided by the enclosing
    /// type.
    pub struct Data;
    impl DataSeg for Data {}
    
    /// Marker that represents both [`Head`] and [`Data`].
    pub struct Both;
    impl HeadSeg for Both {}
    impl DataSeg for Both {}
}
use segment::*;

/// A package based on a slice
///
/// Constructing variants of this type that include header data verifies
/// the signature of the header, hashes the entries' metadata, and checks that
/// hash against the hash stored in the header.
///
/// # Example
/// ```no_run
/// use pkgar_core::{PackageBuf, PackageHead, segment};
/// # let buf = vec![];
/// # let pkey = sodiumoxide::crypto::sign::PublicKey([0; 32]);
/// // define the contents of buf as a package
/// let pkgbuf = PackageBuf::new(&buf, &pkey)
///     .expect("Parsing/Verifying pkgbuf entries failed");
/// for entries in pkgbuf.entries() {
///     // do something with the entries, maybe use PackageData::read_entry
/// }
/// ```
pub struct PackageBuf<'a, S = Both> {
    // Head and data segments in a single buffer
    src: &'a [u8],
    
    header: Option<Header>,
    entries: &'a [Entry],
    
    _marker: PhantomData<S>,
}

impl<'a, S: HeadSeg> PackageBuf<'a, S> {
    // Bad name
    fn with_head(src: &'a [u8], pkey: &PublicKey) -> Result<PackageBuf<'a, S>, Error> {
        let header = *Header::new(&src, &pkey)?;
        Ok(PackageBuf {
            src,
            header: Some(header),
            entries: header.entries(&src[HEADER_SIZE..])?,
            
            _marker: PhantomData,
        })
    }
}

// I don't like the repitition of this function signature, but it's better than requiring
// PackageBuf::<segment::Head>::new(src, pkey) all the time
impl<'a> PackageBuf<'a, Both> {
    /// Construct a `PackageBuf` from a full pkgar slice. The type returned by
    /// this function implements both [`PackageHead`] and [`PackageData`].
    #[inline]
    pub fn new(src: &'a [u8], pkey: &PublicKey) -> Result<PackageBuf<'a, Both>, Error> {
        PackageBuf::with_head(src, pkey)
    }
}

impl<'a> PackageBuf<'a, Head> {
    /// Construct a `PackageBuf` from the head segment of a pkgar archive. The
    /// type returned by this function implements [`PackageHead`].
    #[inline]
    pub fn from_head(src: &'a [u8], pkey: &PublicKey) -> Result<PackageBuf<'a, Head>, Error> {
        PackageBuf::with_head(src, pkey)
    }
}

impl<'a> PackageBuf<'a, Data> {
    /// Construct a `PackageBuf` from the data segment of a pkgar archive. The
    /// type returned by this function implements [`PackageData`].
    pub fn from_data(src: &'a [u8]) -> PackageBuf<'a, Data> {
        PackageBuf {
            src,
            header: None,
            entries: &[],
            
            _marker: PhantomData,
        }
    }
}

impl<S: HeadSeg> PackageHead for PackageBuf<'_, S> {
    fn header(&self) -> Header {
        self.header
            .expect("Head segment package buf always has a header")
    }
    
    fn entries(&self) -> Iter<'_, Entry> {
        self.entries.iter()
    }
}

impl<S: DataSeg> PackageData for PackageBuf<'_, S> {
    type Err = Error;
    
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        // Have to account for the head portion, when S includes it
        let header_len = self.header.map(|h| h.total_size() )
            .transpose()?
            .unwrap_or(0);
        let start = usize::try_from(offset + header_len)?;
        
        let len = self.src.len();
        if start >= len {
            return Ok(0);
        }
        let mut end = start.checked_add(buf.len())
            .ok_or(Error::Overflow)?;
        if end > len {
            end = len;
        }
        buf.copy_from_slice(&self.src[start..end]);
        Ok(end.checked_sub(start).unwrap())
    }
}

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use std::vec;
    
    use sodiumoxide::crypto::sign;
    
    use crate::{
        Entry, Mode,
        PackageBuf, PackageData, PackageHead,
        test::{
            PACKAGE_ENTRY1, PACKAGE_ENTRY1_PATH,
            PACKAGE_ENTRY2, PACKAGE_ENTRY2_PATH,
            package, ZEROS_PACKAGE,
        },
    };

    #[test]
    fn pkgbuf_zeros() {
        let (pkey, _) = sign::gen_keypair();
        let rslt = PackageBuf::new(&ZEROS_PACKAGE, &pkey);
        
        assert!(rslt.is_err());
    }
    
    #[test]
    fn pkgbuf_separate_segments() {
        let (public_key, secret_key) = sign::gen_keypair();
        let (head, data) = package(public_key, secret_key);
        
        let head_src = PackageBuf::from_head(&head, &public_key)
            .unwrap();
        let entries: Vec<&Entry> = head_src.entries()
            .collect();
        
        // See crate::test for definitions
        assert_eq!(head_src.header().count(), 2);
        
        assert_eq!(entries[0].mode().ok(), Mode::from_bits(0o640));
        assert_eq!(entries[0].path_bytes(), PACKAGE_ENTRY1_PATH);
        assert_eq!(entries[1].mode().ok(), Mode::from_bits(0o644));
        assert_eq!(entries[1].path_bytes(), PACKAGE_ENTRY2_PATH);
        
        let data_src = PackageBuf::from_data(&data);
        let mut buf = vec![0; 1024 * 4];
        
        data_src.read_entry(*entries[0], 0, &mut buf)
            .expect("Failed to fill buffer with entry 0");
        assert_eq!(&buf[..entries[0].size() as usize], PACKAGE_ENTRY1);
        
        data_src.read_entry(*entries[1], 0, &mut buf)
            .expect("Failed to fill buffer with entry 1");
        assert_eq!(&buf[..entries[1].size() as usize], PACKAGE_ENTRY2);
    }
    
    #[test]
    fn pkgbuf_both_segments() {
        let (pkey, skey) = sign::gen_keypair();
        let (mut pkg, mut data) = package(pkey, skey);
        
        pkg.append(&mut data);
        
        let src = PackageBuf::new(&pkg, &pkey)
            .unwrap();
        let mut entries = src.entries();
        let entry1 = *entries.next().unwrap();
        let entry2 = *entries.next().unwrap();
        
        assert_eq!(src.header().count(), 2);
        
        assert_eq!(entry1.mode().ok(), Mode::from_bits(0o640));
        assert_eq!(entry1.path_bytes(), PACKAGE_ENTRY1_PATH);
        assert_eq!(entry2.mode().ok(), Mode::from_bits(0o644));
        assert_eq!(entry2.path_bytes(), PACKAGE_ENTRY2_PATH);
        
        let mut buf = vec![0; 1024 * 4];
        
        src.read_entry(entry1, 0, &mut buf)
            .unwrap();
        assert_eq!(&buf[..entry1.size() as usize], PACKAGE_ENTRY1);
        src.read_entry(entry2, 0, &mut buf)
            .unwrap();
        assert_eq!(&buf[..entry2.size() as usize], PACKAGE_ENTRY2);
    }
}

