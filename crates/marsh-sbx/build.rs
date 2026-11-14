// Release packaging sets MARSH_RELEASE_PACKAGING=1 (CI's host and guest
// builds). That turns on a cfg which refuses the `test-support` feature at
// compile time (src/lib.rs), the same way marsh-contracts refuses `test-breaks`:
// the guard is keyed on the effective `feature = "test-support"` cfg, so it
// also refuses one passed by hand (`RUSTFLAGS='--cfg feature="test-support"'`).
fn main() {
    println!("cargo::rustc-check-cfg=cfg(marsh_release_packaging)");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=MARSH_RELEASE_PACKAGING");
    if std::env::var_os("MARSH_RELEASE_PACKAGING").is_some_and(|value| value == "1") {
        println!("cargo::rustc-cfg=marsh_release_packaging");
    }
}
