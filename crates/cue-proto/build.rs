use std::path::Path;

fn main() {
    let proto_dir = Path::new("proto");
    let protos = [proto_dir.join("envelope.proto")];

    // protox is a pure-Rust protobuf parser: no system `protoc` install
    // required to build this workspace.
    let file_descriptor_set = protox::compile(&protos, [proto_dir]).expect("compile protos");

    prost_build::Config::new()
        .compile_fds(file_descriptor_set)
        .expect("generate rust types from protos");

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
}
