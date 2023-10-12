use std::{
    io::{Read, Write},
    path::Path,
};

use veracrypt::UnmountedVolume;

fn main() {
    let volume_path = Path::new("tests/integration/test.hc");
    let volume = UnmountedVolume::open(volume_path).unwrap();

    let password = "password1234";
    let fs = volume.mount(password).unwrap();

    let files: Vec<_> = fs
        .root_dir()
        .iter()
        .filter_map(|entry| entry.ok())
        .collect();

    let mut f = fs.root_dir().create_file("a.txt").unwrap();
    f.write_all("hello world!".as_bytes()).unwrap();
    f.flush().unwrap();

    //dbg!(&files);
    //let file = files[0].to_file();
    //println!("name: {}", files[0].file_name());

    // let new_contents = "something else hello";
    // file.write_all(new_contents.as_bytes()).unwrap();

    // let mut contents = String::new();
    // file.read_to_string(&mut contents).unwrap();
    // dbg!(contents);
}
