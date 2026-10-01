//! Kleiner Zwischenspeicher für entpackte Chunks, nach Chunknummer in Teile
//! gegliedert, damit parallele Leser sich selten gegenseitig sperren.

use std::sync::{Arc, Mutex};

/// Teile des Speichers.
const TEILE: usize = 16;
/// Chunks je Teil; bei 32 KiB je Chunk zusammen 16 MiB.
const JE_TEIL: usize = 32;

#[derive(Debug, Default)]
struct Teil {
    eintraege: Vec<(u64, Arc<[u8]>, u64)>,
    uhr: u64,
}

#[derive(Debug)]
pub(crate) struct ChunkCache {
    teile: Vec<Mutex<Teil>>,
}

impl ChunkCache {
    pub fn new() -> Self {
        Self {
            teile: (0..TEILE).map(|_| Mutex::new(Teil::default())).collect(),
        }
    }

    fn teil(&self, index: u64) -> std::sync::MutexGuard<'_, Teil> {
        // Ein abgebrochener Leser hinterlässt keine halben Einträge.
        self.teile[(index as usize) % TEILE]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    pub fn get(&self, index: u64) -> Option<Arc<[u8]>> {
        let mut t = self.teil(index);
        t.uhr += 1;
        let uhr = t.uhr;
        let e = t.eintraege.iter_mut().find(|e| e.0 == index)?;
        e.2 = uhr;
        Some(Arc::clone(&e.1))
    }

    pub fn put(&self, index: u64, data: Arc<[u8]>) {
        let mut t = self.teil(index);
        t.uhr += 1;
        let uhr = t.uhr;
        if t.eintraege.iter().any(|e| e.0 == index) {
            return;
        }
        if t.eintraege.len() < JE_TEIL {
            t.eintraege.push((index, data, uhr));
        } else if let Some(alt) = t.eintraege.iter_mut().min_by_key(|e| e.2) {
            *alt = (index, data, uhr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdraengt_den_aeltesten() {
        let c = ChunkCache::new();
        for i in 0..(JE_TEIL as u64 + 1) {
            c.put(i * TEILE as u64, Arc::from(vec![i as u8]));
        }
        assert!(c.get(0).is_none());
        assert_eq!(c.get(TEILE as u64).as_deref(), Some(&[1u8][..]));
    }
}
