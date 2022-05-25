use std::{error::Error, path::Path};

#[test]
fn it_decrypts_file() -> Result<(), Box<dyn Error>> {
    let filename = Path::new("./test.hc");
    let password = "password1234";

    let mut volume = veracrypt::Volume::new(filename);

    volume.decrypt(password)?;

    Ok(())
}
