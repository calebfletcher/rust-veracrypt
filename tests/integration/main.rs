use std::{error::Error, path::PathBuf};

#[test]
fn it_decrypts_file() -> Result<(), Box<dyn Error>> {
    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("tests/integration");
    let volume_path = test_dir.join("test.hc");
    let password = "password1234";

    let mut volume = veracrypt::Volume::open(volume_path)?;

    volume.decrypt(password)?;

    Ok(())
}
