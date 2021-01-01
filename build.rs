use std::{path::PathBuf, process::Command};

fn main() {
    let src_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let test_dir = &format!("{}/tests/testdata", src_dir.to_str().unwrap());

    println!("cargo:rerun-if-changed={}", format!("{}/test.c", test_dir));
    cc::Build::new()
        .compiler("/usr/bin/clang-10")
        .no_default_flags(true)
        .warnings(false)
        .cargo_metadata(false)
        .file(format!("{}/test.c", test_dir))
        .include(test_dir)
        .include("/usr/include/x86_64-linux-gnu")
        .flag("-g")
        .flag("-O2")
        .flag("--target=bpf")
        .out_dir(test_dir)
        .compile("test");

    std::fs::remove_file(format!("{}/libtest.a", test_dir)).unwrap();

    let output = Command::new("uname")
        .arg("-r")
        .output()
        .expect("failed to determine kernel version");
    let k_version = String::from_utf8(output.stdout).unwrap();
    let k_version = k_version.trim_end_matches('\n');
    let parts: Vec<&str> = k_version.split('.').collect();
    let major = parts[0].parse::<u32>().unwrap();
    let minor = parts[1].parse::<u32>().unwrap();

    if major >= 5 && minor >= 6 {
        println!("cargo:rustc-cfg=batch");
    }
}
