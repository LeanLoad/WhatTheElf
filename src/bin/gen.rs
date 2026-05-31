use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use whattheelf::cases;

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = root.join("fixtures");

    fs::create_dir_all(&out)?;
    for case in cases::ALL {
        let dst = out.join(case.id);
        fs::write(&dst, case.image().into_bytes())?;

        let mut permissions = fs::metadata(&dst)?.permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        fs::set_permissions(&dst, permissions)?;
        println!("{}", dst.strip_prefix(root)?.display());
    }

    Ok(())
}
