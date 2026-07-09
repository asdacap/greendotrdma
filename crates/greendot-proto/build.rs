fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Without the grpc feature the crate is the pure domain model — no
    // protoc/codegen (greendot-client builds this way).
    if std::env::var_os("CARGO_FEATURE_GRPC").is_some() {
        grpc::compile()?;
    }
    println!("cargo:rerun-if-changed=proto/helper.proto");
    Ok(())
}

#[cfg(feature = "grpc")]
mod grpc {
    pub fn compile() -> Result<(), Box<dyn std::error::Error>> {
        tonic_build::configure()
            .build_client(true)
            .build_server(true)
            .compile_protos(&["proto/helper.proto"], &["proto"])?;
        Ok(())
    }
}

#[cfg(not(feature = "grpc"))]
mod grpc {
    pub fn compile() -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}
