use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use whattheelf::elf::Image;
use whattheelf::{cases, crashes};

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = root.join("fixtures");
    fs::create_dir_all(&out)?;

    // Structural invariant-violation cases and fuzzer-found crashes both emit an
    // ELF image keyed by id; write each to fixtures/.
    let images = cases::ALL
        .iter()
        .map(|c| (c.id, c.image()))
        .chain(crashes::ALL.iter().map(|c| (c.id, c.image())));

    for (id, image) in images {
        write_fixture(&out.join(id), image)?;
        println!("{}", out.join(id).strip_prefix(root)?.display());
    }

    Ok(())
}

fn write_fixture(dst: &Path, image: Image) -> Result<(), Box<dyn Error>> {
    fs::write(dst, image.into_bytes())?;
    let mut permissions = fs::metadata(dst)?.permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(dst, permissions)?;
    Ok(())
}
