//! Kern von stratum: read-only Image-Zugriff, Integritäts-Hashes,
//! Partitionserkennung und der [`Analyzer`]-Trait für Plugins.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod analyzer;
pub mod error;
pub mod hash;
pub mod image;
pub mod partition;

pub use analyzer::{Analyzer, AnalyzerError, Finding};
pub use error::ImageError;
pub use hash::{hash_bytes, hash_image, ImageHashes};
pub use image::ImageReader;
pub use partition::{
    scan_partitions, FsHint, Guid, Partition, PartitionScheme, PartitionTable, PartitionType,
};
