// This source code can be freely used for research purposes.
// For any other purpose, please contact the authors.

fn main() {
    tonic_build::compile_protos("proto/message.proto").unwrap();
}
