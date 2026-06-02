//! Smoke test proving the shared fixture-path resolution that every later
//! module's parity tests depend on.

mod common;

use common::{crypto_core_fixtures, sdk_py_fixtures};

#[test]
fn shared_fixture_trees_resolve_to_existing_directories() {
    let crypto_core = crypto_core_fixtures();
    assert!(
        crypto_core.is_dir(),
        "crypto-core fixtures must resolve to a directory: {}",
        crypto_core.display()
    );
    assert!(
        crypto_core.join("hash").is_dir(),
        "expected the hash fixtures under {}",
        crypto_core.display()
    );

    let sdk_py = sdk_py_fixtures();
    assert!(
        sdk_py.is_dir(),
        "sdk-py fixtures must resolve to a directory: {}",
        sdk_py.display()
    );
    assert!(
        sdk_py.join("hash").is_dir(),
        "expected the hash fixtures under {}",
        sdk_py.display()
    );
}
