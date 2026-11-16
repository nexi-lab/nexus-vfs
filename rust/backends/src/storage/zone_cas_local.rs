//! Local immutable content namespaces owned by individual replicated zones.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use kernel::abc::object_store::ObjectStore;

use super::cas_local::CasLocalBackend;

/// One physical CAS namespace. Metadata pointers do not grant access to blobs
/// stored in a different zone, including when their hashes are already known.
pub struct ZoneCasLocal {
    zone_id: String,
    backend: Arc<CasLocalBackend>,
}

impl ZoneCasLocal {
    pub fn zone_id(&self) -> &str {
        &self.zone_id
    }

    /// Install the same backend in the zone's VFS mount.
    pub fn backend(&self) -> Arc<dyn ObjectStore> {
        self.backend.clone()
    }

    /// Serve the exact immutable object, including a chunk manifest.
    pub fn read_blob(&self, content_id: &str) -> io::Result<Vec<u8>> {
        self.backend
            .as_cas()
            .expect("CasLocalBackend owns a CAS engine")
            .transport()
            .read_blob(content_id)
    }

    /// Read a logical file from this namespace, assembling its local chunks.
    pub fn read_file(&self, content_id: &str) -> Result<Vec<u8>, kernel::cas_engine::CASError> {
        self.backend
            .as_cas()
            .expect("CasLocalBackend owns a CAS engine")
            .read_content(content_id)
    }
}

/// The owning runtime prepares the zones it admits. Reads only consult prepared
/// namespaces; a remote request cannot open storage or enumerate other zones.
pub struct ZoneCasLocalStores {
    root: PathBuf,
    stores: RwLock<HashMap<String, Arc<ZoneCasLocal>>>,
}

impl ZoneCasLocalStores {
    pub fn open(root: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.canonicalize()?,
            stores: RwLock::new(HashMap::new()),
        })
    }

    /// Prepare one canonical data-zone directory with durable CAS publication.
    /// The namespace is derived from the validated zone identity at this single
    /// boundary, rather than selected by file metadata or a remote request.
    pub fn prepare(&self, zone_id: &str) -> io::Result<Arc<ZoneCasLocal>> {
        contracts::validate_zone_id_for(contracts::ZoneIdUse::TenantCreate, zone_id)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if let Some(store) = self.get(zone_id)? {
            return Ok(store);
        }
        let mut stores = self
            .stores
            .write()
            .map_err(|_| io::Error::other("zone content registry is unavailable"))?;
        if let Some(store) = stores.get(zone_id) {
            return Ok(Arc::clone(store));
        }
        let directory = self.root.join(zone_id);
        std::fs::create_dir_all(&directory)?;
        if directory.canonicalize()? != directory {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "zone content directory must retain its own physical namespace",
            ));
        }
        let backend = Arc::new(CasLocalBackend::new_durable(&directory)?);
        let store = Arc::new(ZoneCasLocal {
            zone_id: zone_id.to_owned(),
            backend,
        });
        stores.insert(zone_id.to_owned(), Arc::clone(&store));
        Ok(store)
    }

    /// Get a prepared namespace without creating storage or following a path.
    pub fn get(&self, zone_id: &str) -> io::Result<Option<Arc<ZoneCasLocal>>> {
        Ok(self
            .stores
            .read()
            .map_err(|_| io::Error::other("zone content registry is unavailable"))?
            .get(zone_id)
            .cloned())
    }
}
