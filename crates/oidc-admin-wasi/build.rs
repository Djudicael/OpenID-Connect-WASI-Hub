use std::env;
use std::path::PathBuf;

const REQUIRED_ADMIN_ASSETS: &[&str] = &[
    "../../front/admin/dist/index.html",
    "../../front/admin/dist/js/index.js",
    "../../front/admin/dist/style/bundle.css",
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));

    for relative_path in REQUIRED_ADMIN_ASSETS {
        println!("cargo:rerun-if-changed={relative_path}");

        let asset_path = manifest_dir.join(relative_path);
        if !asset_path.exists() {
            panic!(
                "missing embedded admin asset: {}\n\nBuild the admin UI first:\n  npm --prefix front/admin run build",
                asset_path.display()
            );
        }
    }
}
