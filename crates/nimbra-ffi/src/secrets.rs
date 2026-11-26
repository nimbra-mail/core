//! Where the engine keeps its secrets (refresh tokens, passwords, the store's key), when
//! the app keeps them itself. The core asks the `keyring` crate for every one of them; this
//! hands those requests to a `SecretStore` the app implements (on iOS, the Keychain with
//! the accessibility it chooses, such as after first unlock, this device only, so that
//! background refresh can read them and backups carry none).
//!
//! Without one, `keyring`'s own Apple backend is used, which is the Keychain too.
//! Secrets never pass through anything else here, and nothing here logs.

use std::any::Any;
use std::sync::Arc;

/// Why a secret could not be read or written. `NotFound` is the only answer that means
/// there is none: anything else is an error, never "signed out".
#[derive(Debug, uniffi::Error)]
pub enum SecretError {
    /// There is no such item.
    NotFound,
    /// The Keychain refused or could not be reached (locked, denied). Never shown with the
    /// secret in it.
    Unavailable { message: String },
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::NotFound => f.write_str("no such item"),
            SecretError::Unavailable { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for SecretError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for SecretError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        SecretError::Unavailable {
            message: format!("the app's secret store failed: {}", error.reason),
        }
    }
}

/// The app's Keychain. `service` and `account` name an item (a generic password); the
/// engine uses service "nimbra". Called from background threads, never the main one.
#[uniffi::export(with_foreign)]
pub trait SecretStore: Send + Sync {
    fn get(&self, service: String, account: String) -> Result<Vec<u8>, SecretError>;
    fn set(&self, service: String, account: String, secret: Vec<u8>) -> Result<(), SecretError>;
    fn delete(&self, service: String, account: String) -> Result<(), SecretError>;
}

/// Routes every `keyring::Entry` the core makes to `store`, from now on. Process-wide.
pub(crate) fn install(store: Arc<dyn SecretStore>) {
    keyring::set_default_credential_builder(Box::new(Builder { store }));
}

struct Builder {
    store: Arc<dyn SecretStore>,
}

impl keyring::credential::CredentialBuilderApi for Builder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<keyring::credential::Credential>> {
        Ok(Box::new(Item {
            store: self.store.clone(),
            service: service.to_string(),
            user: user.to_string(),
        }))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> keyring::credential::CredentialPersistence {
        keyring::credential::CredentialPersistence::UntilDelete
    }
}

struct Item {
    store: Arc<dyn SecretStore>,
    service: String,
    user: String,
}

fn keyring_error(error: SecretError) -> keyring::Error {
    match error {
        SecretError::NotFound => keyring::Error::NoEntry,
        SecretError::Unavailable { message } => {
            keyring::Error::NoStorageAccess(Box::new(SecretError::Unavailable { message }))
        }
    }
}

impl keyring::credential::CredentialApi for Item {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        self.store
            .set(self.service.clone(), self.user.clone(), secret.to_vec())
            .map_err(keyring_error)
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        self.store
            .get(self.service.clone(), self.user.clone())
            .map_err(keyring_error)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        self.store
            .delete(self.service.clone(), self.user.clone())
            .map_err(keyring_error)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    // Names the item only: the default would print nothing secret either, but this says so.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretStore item {}/{}", self.service, self.user)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A Keychain in memory, for tests.
    #[derive(Default)]
    pub(crate) struct Memory(pub Mutex<HashMap<(String, String), Vec<u8>>>);

    impl SecretStore for Memory {
        fn get(&self, service: String, account: String) -> Result<Vec<u8>, SecretError> {
            let items = self.0.lock().unwrap();
            items
                .get(&(service, account))
                .cloned()
                .ok_or(SecretError::NotFound)
        }
        fn set(
            &self,
            service: String,
            account: String,
            secret: Vec<u8>,
        ) -> Result<(), SecretError> {
            self.0.lock().unwrap().insert((service, account), secret);
            Ok(())
        }
        fn delete(&self, service: String, account: String) -> Result<(), SecretError> {
            self.0
                .lock()
                .unwrap()
                .remove(&(service, account))
                .map(|_| ())
                .ok_or(SecretError::NotFound)
        }
    }

    /// The one in-memory Keychain every test uses: the builder is process-wide, and no test
    /// may reach the real Keychain (it would ask the user).
    pub(crate) fn memory() -> Arc<Memory> {
        static MEMORY: std::sync::OnceLock<Arc<Memory>> = std::sync::OnceLock::new();
        MEMORY
            .get_or_init(|| {
                let memory = Arc::new(Memory::default());
                install(memory.clone());
                memory
            })
            .clone()
    }

    #[test]
    fn the_core_reads_and_writes_through_the_apps_store() {
        let memory = memory();
        // The way the core asks for a sign-in.
        let entry = keyring::Entry::new("nimbra", "test-item").unwrap();
        assert!(matches!(entry.get_password(), Err(keyring::Error::NoEntry)));
        entry.set_password("s3cret").unwrap();
        assert_eq!(entry.get_password().unwrap(), "s3cret");
        assert_eq!(
            memory
                .0
                .lock()
                .unwrap()
                .get(&("nimbra".into(), "test-item".into())),
            Some(&b"s3cret".to_vec())
        );
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(keyring::Error::NoEntry)));
    }

    #[test]
    fn a_refusal_is_not_there_is_none() {
        struct Locked;
        impl SecretStore for Locked {
            fn get(&self, _: String, _: String) -> Result<Vec<u8>, SecretError> {
                Err(SecretError::Unavailable {
                    message: "locked".into(),
                })
            }
            fn set(&self, _: String, _: String, _: Vec<u8>) -> Result<(), SecretError> {
                Err(SecretError::Unavailable {
                    message: "locked".into(),
                })
            }
            fn delete(&self, _: String, _: String) -> Result<(), SecretError> {
                Err(SecretError::Unavailable {
                    message: "locked".into(),
                })
            }
        }
        let item = Item {
            store: Arc::new(Locked),
            service: "nimbra".into(),
            user: "x".into(),
        };
        use keyring::credential::CredentialApi as _;
        assert!(matches!(
            item.get_secret(),
            Err(keyring::Error::NoStorageAccess(_))
        ));
    }
}
