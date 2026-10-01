//! `Read` und `Seek` über einen Snapshot, etwa für den NTFS-Parser.

use std::io::{self, Read, Seek, SeekFrom};

use crate::{Source, Volume};

/// Lesbare, suchbare Sicht auf einen Snapshot.
#[derive(Debug, Clone)]
pub struct StoreReader<'v, S: Source> {
    volume: &'v Volume<S>,
    store: usize,
    size: u64,
    position: u64,
}

impl<'v, S: Source> StoreReader<'v, S> {
    pub(crate) fn new(volume: &'v Volume<S>, store: usize, size: u64) -> Self {
        Self {
            volume,
            store,
            size,
            position: 0,
        }
    }

    /// Größe des Snapshots in Byte.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl<S: Source> Read for StoreReader<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.size - self.position) as usize;
        self.volume
            .read_at(self.store, self.position, &mut buf[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        self.position += n as u64;
        Ok(n)
    }
}

impl<S: Source> Seek for StoreReader<'_, S> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let neu = match pos {
            SeekFrom::Start(o) => Some(o),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.position.checked_add_signed(d),
        };
        let neu = neu.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Position außerhalb des Snapshots",
            )
        })?;
        self.position = neu;
        Ok(neu)
    }
}
