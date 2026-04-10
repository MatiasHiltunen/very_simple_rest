fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
        let stack_size = "16777216";
        let linker_arg = if target_env == "msvc" {
            format!("/STACK:{stack_size}")
        } else {
            format!("-Wl,--stack,{stack_size}")
        };
        println!("cargo:rustc-link-arg-bin=vsr={linker_arg}");
    }
}
