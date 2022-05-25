use std::path::Path;

use veracrypt::Volume;

fn main() {
    let volume_path = Path::new("tests/integration/test.hc");
    let mut volume = Volume::open(volume_path).unwrap();

    let password = "password1234";
    volume.decrypt(password).unwrap();
}
