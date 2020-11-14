use errno::{set_errno, Errno};
use std::{marker::PhantomData, mem::size_of, os::raw::c_void};

use crate::error::XDPError;
use crate::map_types::MapType;
use crate::program::XDPProgram;
use crate::result::XDPResult;
use crate::utils;

/// Flags that control map `update` behaviour.
#[repr(u32)]
pub enum MapFlags {
    /// Create a new element or update an existing element.
    BpfAny = libbpf_sys::BPF_ANY,

    /// Create a new element only if it did not exist.
    BpfNoExist = libbpf_sys::BPF_NOEXIST,

    /// Update an existing element.
    BpfExist = libbpf_sys::BPF_EXIST,
}

/// Struct to hold key/value pair when getting all items from a map.
pub struct KeyValue<K, V> {
    pub key: K,
    pub value: V,
}

pub struct Map<K, V> {
    map_fd: i32,
    _key: PhantomData<K>,
    _val: PhantomData<V>,
    map_type: MapType,
}

impl<K: Default, V: Default> Map<K, V> {
    /// Create and load `map_name`. This will fail if the requested key/value sizes
    /// doesn't match the key/value sizes defined in the underlying eBPF map.
    pub fn new(xdp: &XDPProgram, map_name: &str) -> XDPResult<Map<K, V>> {
        let name = utils::str_to_cstring(map_name)?;
        let map_fd =
            unsafe { libbpf_sys::bpf_object__find_map_fd_by_name(xdp.object, name.as_ptr()) };

        Map::new_map_from_fd(xdp, map_fd, map_name)
    }

    /// Create, load and "pin" (if not already pinned) `map_name`. This will fail if the requested
    /// key/value sizes don't match the key/value sizes defined in the underlying eBPF map, or
    /// pinning the map fails.
    pub fn new_pinned(xdp: &XDPProgram, map_name: &str, pin_path: &str) -> XDPResult<Map<K, V>> {
        let s = utils::str_to_cstring(pin_path)?;
        let map_fd = unsafe { libbpf_sys::bpf_obj_get(s.as_ptr()) };
        if map_fd > 0 {
            println!("Found pinned map with fd {}", map_fd);
            return Map::new_map_from_fd(xdp, map_fd, map_name);
        }

        let m: Map<K, V> = Map::new(xdp, map_name)?;
        let rc = unsafe { libbpf_sys::bpf_obj_pin(m.map_fd, s.as_ptr()) };
        check_rc(rc, m, "Error pinning map")
    }

    fn new_map_from_fd(xdp: &XDPProgram, map_fd: i32, map_name: &str) -> XDPResult<Map<K, V>> {
        let name = utils::str_to_cstring(map_name)?;
        let (map, map_def) = unsafe {
            let map = libbpf_sys::bpf_object__find_map_by_name(xdp.object, name.as_ptr());

            let map_def = libbpf_sys::bpf_map__def(map);
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

        let map_type: MapType = mtype.into();
        Ok(Map {
            map_fd,
            _key: PhantomData,
            _val: PhantomData,
            map_type,
        })
    }

    #[inline]
    pub fn update(&mut self, key: &K, value: &V, flags: u32) -> XDPResult<()> {
        let rc = unsafe {
            libbpf_sys::bpf_map_update_elem(
                self.map_fd,
                key as *const _ as *const c_void,
                value as *const _ as *const c_void,
                flags.into(),
            )
        };

        check_rc(rc, (), "Error updating elem")
    }

    #[inline]
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
        let rc = unsafe {
            libbpf_sys::bpf_map_delete_elem(self.map_fd, key as *const _ as *const c_void)
        };

        check_rc(rc, (), "Error deleting elem")
    }

    #[inline]
    pub fn lookup(&self, key: &K) -> XDPResult<V> {
        let mut value: V = Default::default();
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                self.map_fd,
                key as *const _ as *const c_void,
                &mut value as *mut _ as *mut c_void,
            )
        };

        check_rc(rc, value, "Error looking up elem")
    }

    pub fn get_next_key(&self, key: &K, next_key: &mut K) -> XDPResult<()> {
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                self.map_fd,
                key as *const _ as *const c_void,
                next_key as *mut _ as *mut c_void,
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
        let mut lkey: K = Default::default();
        let mut next_key: K = Default::default();

        let mut result = Vec::new();
        while let Ok(_) = self.get_next_key(&lkey, &mut next_key) {
            result.push(KeyValue {
                key: lkey,
                value: self.lookup(&lkey)?,
            });
            lkey = next_key;
        }

        result.push(KeyValue {
            key: lkey,
            value: self.lookup(&lkey)?,
        });

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
