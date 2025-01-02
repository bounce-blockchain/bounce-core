use dashmap::DashMap;
use std::error::Error;
use std::sync::Arc;

use eth_trie::{MemDBError, DB};

#[derive(Default, Debug)]
pub struct MemoryDB {
    light: bool,
    storage: Arc<DashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryDB {
    pub fn new(light: bool) -> Self {
        MemoryDB {
            light,
            storage: Arc::new(DashMap::new()),
        }
    }
}

impl DB for MemoryDB {
    type Error = MemDBError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.storage.get(key).map(|v| v.clone()))
    }

    fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.storage.insert(key.to_vec(), value);
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        if self.light {
            self.storage.remove(key);
        }
        Ok(())
    }

    fn insert_batch(&self, keys: Vec<Vec<u8>>, values: Vec<Vec<u8>>) -> Result<(), Self::Error> {
        use rayon::prelude::*;
        keys.into_par_iter()
            .zip(values.into_par_iter())
            .for_each(|(key, value)| {
                self.storage.insert(key, value);
            });
        Ok(())
    }

    fn remove_batch(&self, keys: &[Vec<u8>]) -> Result<(), Self::Error> {
        use rayon::prelude::*;
        keys.par_iter().for_each(|key| {
            self.storage.remove(key);
        });
        Ok(())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        // Example: Implement flush logic, such as syncing to a persistent store.
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.storage.len())
    }

    #[cfg(test)]
    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.storage.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memdb_get() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test-key", b"test-value".to_vec()).unwrap();
        let v = memdb.get(b"test-key").unwrap().unwrap();

        assert_eq!(v, b"test-value")
    }

    #[test]
    fn test_memdb_remove() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test", b"test".to_vec()).unwrap();

        memdb.remove(b"test").unwrap();
        let contains = memdb.get(b"test").unwrap();
        assert_eq!(contains, None)
    }

    #[test]
    fn test_memdb_batch_insert() {
        let memdb = MemoryDB::new(true);
        let keys = vec![b"key1".to_vec(), b"key2".to_vec()];
        let values = vec![b"value1".to_vec(), b"value2".to_vec()];

        memdb.insert_batch(keys.clone(), values.clone()).unwrap();

        for i in 0..keys.len() {
            let value = memdb.get(&keys[i]).unwrap().unwrap();
            assert_eq!(value, values[i]);
        }
    }

    #[test]
    fn test_memdb_batch_remove() {
        let memdb = MemoryDB::new(true);
        let keys = vec![b"key1".to_vec(), b"key2".to_vec()];
        let values = vec![b"value1".to_vec(), b"value2".to_vec()];

        memdb.insert_batch(keys.clone(), values).unwrap();
        memdb.remove_batch(&keys).unwrap();

        for key in keys {
            let value = memdb.get(&key).unwrap();
            assert_eq!(value, None);
        }
    }
}
