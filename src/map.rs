use errno::{set_errno, Errno};
use std::{marker::PhantomData, mem::size_of, os::raw::c_void};

use crate::map_batch::*;
use crate::map_common as mc;
use crate::map_common::{MapLike, MapValue};
use crate::object::XDPLoadedObject;
use crate::result::XDPResult;
use crate::{KeyValue, MapType, XDPError};

/// Used for working with normal eBPF maps.
pub struct Map<K, V> {
    map_fd: i32,
    _key: PhantomData<K>,
    _val: PhantomData<V>,
    map_type: MapType,
    max_entries: u32,
}

impl<K: Default, V: Default> Map<K, V> {
    /// Create a new map.
    pub fn create(
        map_type: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> XDPResult<Map<K, V>> {
        if map_type.is_per_cpu() {
            set_errno(Errno(22));
            fail!("Improper map type, use rxdp::PerCpuMap::create");
        }
        Map::<K, V>::_create(map_type, key_size, value_size, max_entries, map_flags, true)
    }

    pub(crate) fn _create(
        map_type: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        check_batch: bool,
    ) -> XDPResult<Map<K, V>> {
        let map_fd = mc::create_map(map_type, key_size, value_size, max_entries, map_flags);

        if check_batch {
            let _ = is_batching_supported();
        }

        let m = Map {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
            max_entries,
        };

        mc::check_rc(map_fd, m, "Error creating new map")
    }

    /// Get access to the eBPF map `map_name`. This will fail if the requested key/value sizes
    /// don't match the key/value sizes defined in the ELF file.
    pub fn new(xdp: &XDPLoadedObject, map_name: &str) -> XDPResult<Map<K, V>> {
        let (map_fd, vsize, mtype, max_entries) = mc::validate_map::<K>(xdp, map_name)?;

        let map_type: MapType = mtype.into();
        if map_type.is_per_cpu() {
            set_errno(Errno(22));
            fail!("Improper map type, use rxdp::PerCPUMap::new");
        }

        let req_val_size = size_of::<V>() as u32;
        if req_val_size != vsize {
            fail!(
                "Incorrect value size, XDP map has size: {}, requested value size is {}.",
                vsize,
                req_val_size,
            );
        }

        Ok(Map {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
            max_entries,
        })
    }
}

impl<K: Default + Copy, V: Default> MapLike<K, V> for Map<K, V> {
    fn update_batching_not_supported(&self) -> bool {
        !is_batching_supported()
    }

    fn map_fd(&self) -> i32 {
        self.map_fd
    }

    fn map_type(&self) -> MapType {
        self.map_type
    }

    fn max_entries(&self) -> u32 {
        self.max_entries
    }

    fn lookup_batch_impl(
        &self,
        batch_size: u32,
        next_key: Option<u32>,
        delete: bool,
    ) -> XDPResult<BatchResult<K, MapValue<V>>> {
        let mut keys: Vec<K> = Vec::with_capacity(batch_size as usize);
        let mut vals: Vec<V> = Vec::with_capacity(batch_size as usize);
        keys.resize_with(batch_size as usize, Default::default);
        vals.resize_with(batch_size as usize, Default::default);

        let r = mc::lookup_batch_prealloc(
            self.map_fd,
            batch_size,
            next_key,
            &mut keys,
            &mut vals,
            delete,
        )?;
        let mut result = Vec::with_capacity(r.num_items as usize);
        populate_batch_result(r.num_items, &mut result, &mut keys, &mut vals);

        Ok(BatchResult {
            items: result,
            next_key: r.next_key,
            num_items: r.num_items,
        })
    }

    fn _items(&self) -> XDPResult<Vec<KeyValue<K, MapValue<V>>>> {
        let mut key: K = Default::default();
        let mut result = Vec::with_capacity(self.max_entries as usize);
        let mut more = {
            let first_key: *const i32 = std::ptr::null();
            self.get_next_key(first_key as *const c_void, &mut key)
                .is_ok()
        };

        while more {
            // Handle special maps. DEV_MAP holds references to network interfaces, which can
            // be deleted, causing the lookup for that key to fail. However, there could be more
            // values further in the map.
            let maybe_val = self.lookup(&key);
            if self.map_type == MapType::DevMap && maybe_val.is_err() {
                more = self
                    .get_next_key(&key as *const _ as *const c_void, &mut key)
                    .is_ok();
                continue;
            }

            result.push(KeyValue {
                key: key,
                value: maybe_val?,
            });

            more = self
                .get_next_key(&key as *const _ as *const c_void, &mut key)
                .is_ok();
        }

        Ok(result)
    }

    fn items(&self) -> XDPResult<Vec<KeyValue<K, MapValue<V>>>> {
        if self.map_type == MapType::DevMap || self.max_entries < 50 || !is_batching_supported() {
            return self._items();
        }
        let mut keys: Vec<K> = Vec::with_capacity(BATCH_SIZE as usize);
        let mut vals: Vec<V> = Vec::with_capacity(BATCH_SIZE as usize);

        let mut result = Vec::with_capacity(BATCH_SIZE as usize);
        let mut next_key = None;

        loop {
            keys.resize_with(BATCH_SIZE as usize, Default::default);
            vals.resize_with(BATCH_SIZE as usize, Default::default);
            let r = mc::lookup_batch_prealloc(
                self.map_fd,
                BATCH_SIZE,
                next_key,
                &mut keys,
                &mut vals,
                false,
            )?;
            populate_batch_result(r.num_items, &mut result, &mut keys, &mut vals);

            if r.next_key.is_none() {
                break;
            }
            next_key = r.next_key;
        }

        Ok(result)
    }
}

fn populate_batch_result<K, V>(
    n: u32,
    result: &mut Vec<KeyValue<K, MapValue<V>>>,
    keys: &mut Vec<K>,
    vals: &mut Vec<V>,
) {
    vals.truncate(n as usize);
    for k in keys.drain(..n as usize).rev() {
        result.push(KeyValue {
            key: k,
            value: MapValue::Single(vals.pop().unwrap()),
        })
    }
}
