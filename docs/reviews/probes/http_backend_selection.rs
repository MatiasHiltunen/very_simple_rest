//! Review-only compile probe: AxumHttpServer is absent on commit 7c27c9bb3.
fn main() {
    println!(
        "{}",
        std::any::type_name::<vsr_runtime::http::AxumHttpServer>()
    );
}
