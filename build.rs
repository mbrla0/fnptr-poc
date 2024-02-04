use std::path::PathBuf;

fn main() {
	println!("cargo:rerun-if-changed=src/sup/sup.c");
	println!("cargo:rerun-if-changed=src/sup/sup.h");

	cc::Build::new()
		.file("src/sup/sup.c")
		.compile("sup");

	let mut path = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
	path.push("sup.rs");

	bindgen::builder()
		.header("src/sup/sup.h")
		.generate()
		.unwrap()
		.write_to_file(&path)
		.unwrap();
}
