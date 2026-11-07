fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/spawn/guest/v1/guest.proto";
    println!("cargo:rerun-if-changed={proto}");
    let descriptors = protox::compile([proto], ["proto"])?;
    tonic_prost_build::configure().compile_fds(descriptors)?;
    Ok(())
}
