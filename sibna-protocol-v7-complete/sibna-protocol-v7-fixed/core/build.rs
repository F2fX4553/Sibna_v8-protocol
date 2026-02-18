//! Build script for generating C headers via cbindgen

fn main() {
    // Only generate headers when FFI feature is enabled
    #[cfg(feature = "ffi")]
    {
        let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

        match cbindgen::Builder::new()
            .with_crate(&crate_dir)
            .with_language(cbindgen::Language::C)
            .with_include_guard("SIBNA_H")
            .with_include_version(true)
            .with_documentation(true)
            .generate()
        {
            Ok(bindings) => {
                bindings.write_to_file(std::path::PathBuf::from("include/sibna.h"));
            }
            Err(e) => {
                eprintln!("cbindgen error: {}", e);
            }
        }
    }

    // Tell Cargo to rerun this script if needed
    println!("cargo:rerun-if-changed=build.rs");
}
