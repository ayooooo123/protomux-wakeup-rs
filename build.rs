fn main() {
    let opts = hyperschema::Options::new();
    hyperschema::build("spec/schema.json", "wakeup.rs", &opts).unwrap();
}
