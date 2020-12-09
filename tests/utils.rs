use lazy_static::lazy_static;
use libc::if_nametoindex;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::{
    convert::TryInto,
    ffi::CString,
    process::Command,
};

lazy_static! {
    pub static ref TEST_DATA_DIR: String = get_test_dir();
    pub static ref TEST_FILE: String = format!("{}/{}", *TEST_DATA_DIR, "test.elf");
    pub static ref PIN_PATH: String = "/sys/fs/bpf".to_string();
}

pub fn random_string() -> String {
    thread_rng().sample_iter(&Alphanumeric)
                .take(6)
                .collect()
}

pub fn get_test_dir() -> String {
    let exe = std::env::current_exe().unwrap();
    let path = exe.to_str().unwrap();
    let parts: Vec<&str> = path.split('/').skip(1).collect();
    
    format!("/{}/tests/testdata", parts[0])
}

pub fn test_object() -> rxdp::XDPObject {
    rxdp::XDPObject::new(&TEST_FILE).expect("failed to test ELF file")
}

pub fn loaded_object() -> rxdp::XDPLoadedObject {
    test_object().load().unwrap()
}

#[derive(Debug)]
pub struct TestDir {
    pub path: String
}

impl Drop for TestDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

pub fn pin_dir() -> TestDir {
    let folder = random_string();
    let path = format!("{}/{}", *PIN_PATH, folder);
    std::fs::create_dir(&path).unwrap();
    TestDir {path}
}

#[derive(Debug)]
pub struct TestIface {
    pub name: String
}

impl Drop for TestIface {
    fn drop(&mut self) {
        Command::new("ip")
            .arg("link")
            .arg("del")
            .arg(&self.name)
            .status()
            .expect("failed to delete interface");
    }
}

pub fn test_iface() -> TestIface {
    let name = random_string();
    Command::new("ip")
        .arg("link")
        .arg("add")
        .arg(&name)
        .arg("link")
        .arg("eth0")
        .arg("type")
        .arg("macvlan")
        .arg("mode")
        .arg("bridge")
        .status()
        .expect("failed to create interface");

    TestIface{name}
}

pub(crate) fn str_to_cstring(s: &str) -> Result<CString, String> {
    match CString::new(s) {
        Ok(c) => Ok(c),
        Err(e) => {
            let error_msg = format!("Error creating C string: {:?}", e);
            Err(error_msg)
        }
    }
}

pub fn lookup_interface_by_name(name: &str) -> Result<i32, String> {
    let index = unsafe { if_nametoindex(str_to_cstring(name)?.as_ptr()) };
    if index == 0 {
        return Err(format!(
            "Error finding interface index for {}",
            name
        ));
    }

    match (index as i32).try_into() {
        Ok(i) => Ok(i),
        Err(e) => Err(format!(
            "Error converting interface index to 'i32': {}",
            e
        )),
    }
}
