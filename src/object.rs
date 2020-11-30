use crate::error::{get_errno, reset_errno, XDPError};
use crate::program::XDPProgram;
use crate::result::XDPResult;
use crate::utils;

use libbpf_sys as bpf;
use std::collections::{HashMap, HashSet};

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
            Err(XDPError::new("Error creating object from ELF file"))
        } else {
            Ok(Self { object })
        }
    }

    /// Loads any previously pinned maps from the fs and/or sets maps to be pinned. Uses the
    /// default path at `/sys/fs/bpf/` when looking for/pinning maps.
    pub fn pinned_maps(&self, maps: &HashSet<String>, path: Option<&str>) -> XDPResult<()> {
        let base_path = path.unwrap_or("/sys/fs/bpf").trim_end_matches('/');

        unsafe {
            let mut map: *mut bpf::bpf_map = std::ptr::null_mut();
            map = bpf::bpf_map__next(map, self.object);
            while !map.is_null() {
                let map_name = utils::cstring_to_str(bpf::bpf_map__name(map));
                if maps.contains(&map_name) {
                    let pin_path = utils::str_to_cstring(&format!("{}/{}", base_path, map_name))?;
                    let rc = bpf::bpf_map__set_pin_path(map, pin_path.as_ptr());
                    if rc < 0 {
                        return Err(XDPError::new("error setting pin path"));
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
            let rc = bpf::bpf_object__load(obj);
            if rc < 0 {
                return Err(XDPError::new("Error loading object"));
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
            return Err(XDPError::new("No such program"));
        }

        Ok(&self.programs.get(name).unwrap())
    }
}

/// Load a pinned object from a path. Returns the object fd.
pub fn load_pinned_object(pin_path: &str) -> XDPResult<i32> {
    let s = utils::str_to_cstring(pin_path)?;
    let prog_fd = unsafe { bpf::bpf_obj_get(s.as_ptr()) };

    if prog_fd < 0 {
        return Err(XDPError::new("Error retrieving pinned object"));
    }

    Ok(prog_fd)
}
