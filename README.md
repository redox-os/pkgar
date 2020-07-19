# pkgar - Package Archive

pkgar refers to three related items - the file format, the library, and the
command line executable.

The pkgar format is not designed to be the best format for all archive uses,
only the best default format for packages on Redox OS. It is reproducible,
meaning archiving a directory will produce the same results every time. It
provides cryptographic signatures and integrity checking for package files. It
also allows this functionality to be used without storing the entire package
archive, by only storing the package header. Large files, compression,
encryption, and random access are not optimized for. Little endian is currently
assumed, as well as Unix mode flags.

***This specification is currently a work in progress***

## File Format - .pkgar

pkgar is a format for packages may be delivered in a single file (.pkgar), or as
a header file (.pkgar_head) with an associated data file (.pkgar_data). The
purpose of this is to allow downloading a header only and verifying local files
before downloading file data. Concatenating the header and data files creates a
valid single file: `cat example.pkgar_head example.pkgar_data > example.pkgar`

### Header Portion

The header portion is designed to contain the data required to verify files
already installed on disk. It is signed using NaCl (or a compatible
implementation such as libsodium), and contains the blake3, offset, size, mode,
and name of each file. The user and group IDs are left out intentionally, to
support the installation of a package either as root or as a user, for example,
in the user's home directory.

#### Header Struct

The size of the header struct is 136 bytes. All fields are packed.

- signature - 512-bit (64 byte) NaCl signature of header data
- public_key - 256-bit (32 byte) NaCl public key used to generate signature
- blake3 - 256-bit (32 byte) blake3 sum of the entry data
- count - 64-bit count of entry structs, which immediately follow

#### Entry Struct

The size of the entry struct is 308 bytes. All fields are packed.

- blake3 - 256-bit (32 byte) blake3 sum of the file data
- offset - 64-bit little endian offset of file data in the data portion
- size - 64-bit little endian size in bytes of the file data in the data portion
- mode - 32-bit Unix permissions (user, group, other with read, write, execute)
- path - 256 byte NUL-terminated relative path from extract directory

### Data Portion

The data portion is used to look up file data only. It could be compressed to
produce a .pkgar_data.gz file, for example. It can be removed after the install
is completed. It is possible for it to contain holes, invalid data, or
unreferenced data - so long as the blake3 of files identified in the header are
still valid. This data should be removed when an archive is rebuilt.

### Operation

A reader should first verify the header portion's signature matches that of a
valid package source. Then, they should locate the entry for the file of
interest. If desired, they can check if a locally cached file matches the
referenced blake3. If this is not the case, they may access the data portion and
verify that the data at the offset and length in the header entry matches the
blake3. In that case, the data may be retrieved.

## Development
To run the integration tests, you'll need to have pkgar-keys in your $PATH (or the
$PATH of the test script). Clone the repo from
[https://gitlab.redox-os.org/MggMuggins/pkgar-keys]() and run `cargo install --path .`.
Use `test.sh` to run the integration tests.

