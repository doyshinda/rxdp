use crate::error::{get_errno, reset_errno, XDPError};
use crate::program::XDPProgram;
use crate::result::XDPResult;
use crate::utils;

use libbpf_sys as bpf;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Convenience wrapper around an XDP object
pub struct XDPObject {
    object: *mut bpf::bpf_object,
}

/// Struct for an XDP object that has been loaded
pub struct XDPLoadedObject {
    pub(crate) object: *mut bpf::bpf_object,
    programs: HashMap<String, XDPProgram>,
    program_names: Vec<String>,
}

impl XDPObject {
    /// Read the ELF file at `file_path` and attempt to create a bpf object
    pub fn new(file_path: &str) -> XDPResult<Self> {
        // The returned pointer is non-null, even on error. Reset the errno value and check after.
        reset_errno();
        let object = unsafe { bpf::bpf_object__open(utils::str_to_cstring(file_path)?.as_ptr()) };
        if get_errno() != 0 {
            fail!("Error creating object from ELF file")
        } else {
            Ok(Self { object })
        }
    }

    /// Loads any previously pinned maps from the fs and/or sets maps to be pinned. Will use `path`
    /// if provided, else defaults to `/sys/fs/bpf/` when looking for/pinning maps.
    pub fn pinned_maps(&self, maps: &HashSet<String>, path: Option<&str>) -> XDPResult<()> {
        let base_path = path.unwrap_or("/sys/fs/bpf").trim_end_matches('/');

        unsafe {
            let mut map: *mut bpf::bpf_map = std::ptr::null_mut();
            map = bpf::bpf_map__next(map, self.object);
            while !map.is_null() {
                let map_name = utils::cstring_to_str(bpf::bpf_map__name(map));
                if maps.contains(&map_name) {
                    let pin_path = format!("{}/{}", base_path, map_name);
                    sanitize_special_maps(map, &pin_path)?;
                    let pin_path = utils::str_to_cstring(&pin_path)?;
                    let rc = bpf::bpf_map__set_pin_path(map, pin_path.as_ptr());
                    if rc < 0 {
                        fail!("error setting pin path");
                    }
                }
                map = bpf::bpf_map__next(map, self.object);
            }
        }
        Ok(())
    }

    /// Load eBPF maps and programs into the kernel
    pub fn load(self) -> XDPResult<XDPLoadedObject> {
        XDPLoadedObject::new(self)
    }
}

impl XDPLoadedObject {
    fn new(obj: XDPObject) -> XDPResult<Self> {
        let obj = obj.object;
        unsafe {
            let mut prog: *mut bpf::bpf_program = std::ptr::null_mut();
            prog = bpf::bpf_program__next(prog, obj);
            while !prog.is_null() {
                // Workaround for older kernels that fail if `expected_attach_type` is set
                // to anything other than 0.
                bpf::bpf_program__set_expected_attach_type(prog, 0);
                prog = bpf::bpf_program__next(prog, obj);
            }

            if bpf::bpf_object__load(obj) < 0 {
                fail!("Error loading object");
            }
        }

        let mut programs = HashMap::new();
        let mut program_names = Vec::new();

        unsafe {
            let mut prog: *mut bpf::bpf_program = std::ptr::null_mut();
            prog = bpf::bpf_program__next(prog, obj);
            while !prog.is_null() {
                let prog_name = utils::cstring_to_str(bpf::bpf_program__name(prog));
                programs.insert(prog_name.clone(), XDPProgram::new(prog)?);
                program_names.push(prog_name);
                if bpf::bpf_program__get_type(prog) == bpf::BPF_PROG_TYPE_XDP {
                    bpf::bpf_program__set_expected_attach_type(prog, bpf::BPF_XDP);
                }
                prog = bpf::bpf_program__next(prog, obj);
            }
        }

        return Ok(Self {
            object: obj,
            programs,
            program_names,
        });
    }

    /// Returns a list of eBPF program names
    pub fn get_program_names(&self) -> &Vec<String> {
        &self.program_names
    }

    /// Returns a reference to an underlying eBPF program
    pub fn get_program(&self, name: &str) -> XDPResult<&XDPProgram> {
        if !self.programs.contains_key(name) {
            fail!("No such program");
        }

        Ok(&self.programs.get(name).unwrap())
    }
}

/// Load a pinned object from a path. Returns the object fd.
pub fn load_pinned_object(pin_path: &str) -> XDPResult<i32> {
    let s = utils::str_to_cstring(pin_path)?;
    let prog_fd = unsafe { bpf::bpf_obj_get(s.as_ptr()) };

    if prog_fd < 0 {
        fail!("Error retrieving pinned object");
    }

    Ok(prog_fd)
}

unsafe fn sanitize_special_maps(map: *mut bpf::bpf_map, pin_path: &str) -> XDPResult<()> {
    let map_def = bpf::bpf_map__def(map);

    // DEVMAP sets map_flags = 0x80 automatically. In order to reuse the
    // pinned map, the flags have to match.
    if (*map_def).type_ == bpf::BPF_MAP_TYPE_DEVMAP && Path::new(pin_path).exists() {
        let mut existing_flags = (*map_def).map_flags;
        existing_flags |= 0x80;
        if bpf::bpf_map__set_map_flags(map, existing_flags) < 0 {
            fail!("Error setting BPF_MAP_TYPE_DEVMAP map flags for pinned map");
        }
    }

    Ok(())
}
