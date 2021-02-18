use lazy_static::lazy_static;
use libc::if_nametoindex;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::{
    convert::TryInto,
    ffi::CString,
    process::{Command, Stdio},
};

lazy_static! {
    pub static ref TEST_DATA_DIR: String = get_test_dir();
    pub static ref TEST_FILE: String = format!("{}/{}", *TEST_DATA_DIR, "test.o");
    pub static ref PIN_PATH: String = "/sys/fs/bpf".to_string();
}

macro_rules! cmd {
    ( $c:literal, $( $arg:expr ),* ) => {
        {
            let mut cmd = Command::new($c);
            $(
                cmd.arg($arg);
            )*
            cmd
        }
    };
}

macro_rules! ns_cmd {
    ( $c:expr, $( $arg:expr ),* ) => { cmd!("ip", "net", "exe", $c, $($arg),*)  };
}

pub fn random_string() -> String {
    thread_rng().sample_iter(&Alphanumeric).take(6).collect()
}

pub fn get_test_dir() -> String {
    let src_dir = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    format!("{}/tests/testdata", src_dir.to_str().unwrap())
}

pub fn test_object() -> rxdp::XDPObject {
    rxdp::XDPObject::new(&TEST_FILE).expect("failed to test ELF file")
}

pub fn loaded_object() -> rxdp::XDPLoadedObject {
    test_object().load().unwrap()
}

#[derive(Debug)]
pub struct TestDir {
    pub path: String,
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
    TestDir { path }
}

#[derive(Debug)]
pub struct TestIface {
    pub name: String,
    pub ip: String,
    ns: Option<String>,
}

impl TestIface {
    pub fn ping(&self, ip: &str, count: u32) {
        match &self.ns {
            Some(ns) => {
                ns_cmd!(ns, "ping", "-q", "-i", "0.1", "-c", count.to_string(), ip)
                    .stdout(Stdio::null())
                    .status()
                    .expect("failed to ping");
            }
            None => {
                cmd!("ping", "-i", "-q", "0.1", "-c", count.to_string(), ip)
                    .stdout(Stdio::null())
                    .status()
                    .expect("failed to ping");
            }
        }
    }
}

impl Drop for TestIface {
    fn drop(&mut self) {
        match &self.ns {
            Some(_) => (),
            None => {
                cmd!("ip", "link", "del", &self.name)
                    .status()
                    .expect("failed to delete interface");
            }
        }
    }
}

pub fn test_iface() -> TestIface {
    let name = random_string();
    cmd!("ip", "link", "add", &name, "link", "eth0", "type", "macvlan", "mode", "bridge")
        .status()
        .expect("failed to create interface");

    TestIface {
        name,
        ip: "localhost".to_string(),
        ns: None,
    }
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
        return Err(format!("Error finding interface index for {}", name));
    }

    match (index as i32).try_into() {
        Ok(i) => Ok(i),
        Err(e) => Err(format!("Error converting interface index to 'i32': {}", e)),
    }
}

pub struct VethPair {
    pub one: TestIface,
    pub two: TestIface,
}

impl VethPair {
    pub fn new(ip1: &str, ip2: &str) -> VethPair {
        let rand1 = random_string();
        let rand2 = random_string();
        let name1 = format!("veth_{}", rand1);
        let name2 = format!("veth_{}", rand2);
        let ns2 = format!("ns{}", rand2);

        // Add namespace and assign one of the veth to it
        cmd!("ip", "net", "add", &ns2)
            .status()
            .expect("netns setup fail");
        cmd!("ip", "link", "add", &name1, "type", "veth", "peer", "name", &name2, "netns", &ns2)
            .status()
            .expect("veth pair setup fail");

        // Assign IP addresses and routes
        cmd!("ip", "addr", "add", ip1, "dev", &name1)
            .status()
            .expect("set ip fail");
        ns_cmd!(&ns2, "ip", "addr", "add", ip2, "dev", &name2)
            .status()
            .expect("set ip fail");
        ns_cmd!(&ns2, "ip", "link", "set", "up", &name2)
            .status()
            .expect("set up fail");
        ns_cmd!(&ns2, "ip", "route", "add", "default", "via", ip2, "dev", &name2)
            .status()
            .expect("set route fail");
        cmd!("ip", "link", "set", "up", &name1)
            .status()
            .expect("set up failed");
        cmd!("ip", "r", "add", ip2, "dev", &name1)
            .status()
            .expect("root ns route fail");

        VethPair {
            one: TestIface {
                name: name1,
                ip: ip1.to_string(),
                ns: None,
            },
            two: TestIface {
                name: name2,
                ip: ip2.to_string(),
                ns: Some(ns2),
            },
        }
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        cmd!("ip", "net", "del", self.two.ns.as_ref().unwrap())
            .status()
            .expect("cleanup ns failed");
    }
}
