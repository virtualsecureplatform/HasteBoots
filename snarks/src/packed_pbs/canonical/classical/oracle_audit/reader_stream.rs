//! Immutable-file creation for optional concrete interface-event captures.
use super::OracleEvent;
use helper::classical_transcript::audit::ReaderEvent;
use sha2::{Digest, Sha512};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

/// Writer for the independently audited hash/reader companion format.
#[derive(Debug)]
pub struct ReaderStream {
    writer: BufWriter<File>,
    digest: Sha512,
}
impl ReaderStream {
    /// Create a new file; existing evidence is never overwritten.
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut stream = Self {
            writer: BufWriter::new(file),
            digest: Sha512::default(),
        };
        stream.bytes(b"HB_ORACLE_READER_STREAM_V1\n")?;
        Ok(stream)
    }
    fn bytes(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)?;
        self.digest.update(data);
        Ok(())
    }
    fn length(&mut self, length: usize) -> io::Result<()> {
        self.bytes(
            &u64::try_from(length)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "reader event length overflow")
                })?
                .to_le_bytes(),
        )
    }
    /// Record phase 0 (setup), 1 (prove) or 2 (verify). A caller must serialize
    /// events from concurrent workers through the same writer.
    pub fn record(&mut self, phase: u8, event: OracleEvent<'_>) -> io::Result<()> {
        if phase > 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reader event phase",
            ));
        }
        match event {
            OracleEvent::Hash { input, output } => {
                self.bytes(&[1, phase])?;
                self.length(input.len())?;
                self.bytes(input)?;
                self.bytes(&output.0)?;
            }
            OracleEvent::Reader(ReaderEvent::Start { reader, input }) => {
                self.bytes(&[2, phase])?;
                self.bytes(&reader.to_le_bytes())?;
                self.length(input.len())?;
                self.bytes(input)?;
            }
            OracleEvent::Reader(ReaderEvent::Output {
                reader,
                offset,
                bytes,
            }) => {
                self.bytes(&[3, phase])?;
                self.bytes(&reader.to_le_bytes())?;
                self.bytes(&offset.to_le_bytes())?;
                self.length(bytes.len())?;
                self.bytes(bytes)?;
            }
        }
        Ok(())
    }
    /// Flush and fingerprint the captured prefix. Call after the observation
    /// scope has ended; this method does not disable producers itself.
    pub fn finish(&mut self) -> io::Result<String> {
        self.writer.flush()?;
        Ok(self
            .digest
            .clone()
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
}
