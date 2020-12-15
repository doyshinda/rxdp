use std::process::Command;

fn main() {
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
