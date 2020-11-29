use errno::{set_errno, Errno};
use libbpf_sys as bpf;
use std::{marker::PhantomData, mem::size_of, os::raw::c_void};

use crate::error::XDPError;
use crate::map_types::MapType;
use crate::object::XDPLoadedObject;
use crate::result::XDPResult;
use crate::utils;

/// Flags that control map `update` behaviour.
#[repr(u32)]
pub enum MapFlags {
    /// Create a new element or update an existing element.
    BpfAny = bpf::BPF_ANY,

    /// Create a new element only if it did not exist.
    BpfNoExist = bpf::BPF_NOEXIST,

    /// Update an existing element.
    BpfExist = bpf::BPF_EXIST,
}

impl From<MapFlags> for u64 {
    fn from(mp: MapFlags) -> u64 {
        match mp {
            MapFlags::BpfAny => 0u64,
            MapFlags::BpfNoExist => 1u64,
            MapFlags::BpfExist => 2u64,
        }
    }
}

/// Struct to hold key/value pair when getting all items from a map.
#[derive(Debug)]
pub struct KeyValue<K, V> {
    pub key: K,
    pub value: V,
}

/// Struct that handles interacting with the underlying eBPF map.
pub struct Map<K, V> {
    map_fd: i32,
    _key: PhantomData<K>,
    _val: PhantomData<V>,
    map_type: MapType,
}

impl<K: Default, V: Default> Map<K, V> {
    /// Create and load `map_name`. This will fail if the requested key/value sizes
    /// doesn't match the key/value sizes defined in the underlying eBPF map.
    pub fn new(xdp: &XDPLoadedObject, map_name: &str) -> XDPResult<Map<K, V>> {
        let name = utils::str_to_cstring(map_name)?;
        let map_fd = unsafe { bpf::bpf_object__find_map_fd_by_name(xdp.object, name.as_ptr()) };

        Map::new_map_from_fd(xdp, map_fd, map_name)
    }

    fn new_map_from_fd(xdp: &XDPLoadedObject, map_fd: i32, map_name: &str) -> XDPResult<Map<K, V>> {
        let name = utils::str_to_cstring(map_name)?;
        let (map, map_def) = unsafe {
            let map = bpf::bpf_object__find_map_by_name(xdp.object, name.as_ptr());

            let map_def = bpf::bpf_map__def(map);
            (map, map_def)
        };

        if map_fd < 0 || map.is_null() || map_def.is_null() {
            let error_msg = format!("Unable to find map with name '{}'", map_name);
            return Err(XDPError::new(&error_msg));
        }

        // Sanity check key & value sizes.
        let (ksize, vsize, mtype) =
            unsafe { ((*map_def).key_size, (*map_def).value_size, (*map_def).type_) };
        let (req_key_size, req_val_size) = (size_of::<K>() as u32, size_of::<V>() as u32);
        if req_key_size != ksize {
            let error_msg = format!(
                "Incorrect key size, XDP map has size: {}, requested key size is {}.",
                ksize, req_key_size,
            );
            return Err(XDPError::new(&error_msg));
        }

        if req_val_size != vsize {
            let error_msg = format!(
                "Incorrect value size, XDP map has size: {}, requested value size is {}.",
                vsize, req_val_size,
            );
            return Err(XDPError::new(&error_msg));
        }

        Ok(Map {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type: mtype.into(),
        })
    }

    #[inline]
    /// Update an element in the underlying eBPF map.
    pub fn update(&mut self, key: &K, value: &V, flags: MapFlags) -> XDPResult<()> {
        let rc = unsafe {
            bpf::bpf_map_update_elem(
                self.map_fd,
                key as *const _ as *const c_void,
                value as *const _ as *const c_void,
                flags.into(),
            )
        };

        check_rc(rc, (), "Error updating elem")
    }

    #[inline]
    /// Delete an element from the underlying eBPF map.
    pub fn delete(&mut self, key: &K) -> XDPResult<()> {
        // Array map types do not support deletes, do an early return to save a syscall.
        match self.map_type {
            MapType::Array
            | MapType::PerCPUArray
            | MapType::ArrayOfMaps
            | MapType::ProgArray
            | MapType::PerfEventArray => {
                set_errno(Errno(22));
                return Err(XDPError::new("Delete not supported on this map type"));
            }
            _ => (),
        }
        let rc = unsafe { bpf::bpf_map_delete_elem(self.map_fd, key as *const _ as *const c_void) };

        check_rc(rc, (), "Error deleting elem")
    }

    #[inline]
    /// Lookup an element from the underlying eBPF map.
    pub fn lookup(&self, key: &K) -> XDPResult<V> {
        let mut value: V = Default::default();
        let rc = unsafe {
            bpf::bpf_map_lookup_elem(
                self.map_fd,
                key as *const _ as *const c_void,
                &mut value as *mut _ as *mut c_void,
            )
        };

        check_rc(rc, value, "Error looking up elem")
    }

    /// Can be used for partial iteration through a map (as opposed to `items`, which
    /// will return all items in the map).
    pub fn get_next_key<T>(&self, prev_key: &T, key: &mut K) -> XDPResult<()> {
        let rc = unsafe {
            bpf::bpf_map_get_next_key(
                self.map_fd,
                prev_key as *const _ as *const c_void,
                key as *mut _ as *mut c_void,
            )
        };

        check_rc(rc, (), "Error getting next key")
    }

    /// Returns all items in the map. Note that for Array type maps, this will always
    /// return `max_entries` number of items.
    pub fn items(&self) -> XDPResult<Vec<KeyValue<K, V>>>
    where
        K: Copy,
    {
        let mut prev_key: K = Default::default();
        let mut key: K = Default::default();

        let mut result = Vec::new();

        let mut c = 0;
        loop {
            let nxt = if c == 0 {
                let first_key: *const i32 = std::ptr::null();
                self.get_next_key(&first_key, &mut key)
            } else {
                self.get_next_key(&prev_key, &mut key)
            };

            if nxt.is_err() {
                break;
            }

            result.push(KeyValue {
                key: key,
                value: self.lookup(&key)?,
            });
            prev_key = key;
            c += 1;
        }

        Ok(result)
    }
}

fn check_rc<T>(rc: i32, ret: T, err_msg: &str) -> XDPResult<T> {
    if rc < 0 {
        Err(XDPError::new(err_msg))
    } else {
        Ok(ret)
    }
}
