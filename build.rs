use std::env;
use std::path::PathBuf;

fn main() {
    // Build C files
    cc::Build::new()
        .files([
            "codec.c",
            "common.c",
            "deterministic.c",
            "falcon.c",
            "fft.c",
            "fpr.c",
            "keygen.c",
            "rng.c",
            "shake.c",
            "sign.c",
            "vrfy.c",
        ])
        .warnings(false)
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Wpedantic")
        .flag("-Wredundant-decls")
        .flag("-Wshadow")
        .flag("-Wvla")
        .flag("-Wpointer-arith")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-overlength-strings")
        .flag("-O3")
        .flag("-fomit-frame-pointer")
        .flag("-Wno-strict-prototypes")
        .compile("falcon");

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .header("falcon.h")
        .header("deterministic.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}