//! The engine's DNS lookups through the app (iOS: the sandbox has no `/etc/resolv.conf`):
//! server discovery's MX records and brand logos' TXT records. Swift answers them with the
//! system's resolver (`DNSServiceQueryRecord`), so the question goes where any lookup on
//! the device goes and never to a third party. The engine checks the answers
//! (`nimbra_core::dns`).

use std::sync::Arc;

use crate::error::{NimbraError, Result};

/// One MX record: a mail server and its preference (lower is preferred).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MxRecord {
    pub preference: u16,
    pub host: String,
}

#[derive(Debug, uniffi::Error)]
pub enum DnsError {
    /// The lookup failed or timed out.
    Failed { message: String },
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Failed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for DnsError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        DnsError::Failed {
            message: format!("the app's DNS resolver failed: {}", error.reason),
        }
    }
}

/// The app's resolver. Each answers within a few seconds, and is called from background
/// threads.
#[uniffi::export(with_foreign)]
pub trait DnsResolver: Send + Sync {
    /// `domain` is a domain name: its MX records, none when it has none.
    fn mx(&self, domain: String) -> std::result::Result<Vec<MxRecord>, DnsError>;
    /// `name` is a domain name that may have `_` labels (`_dmarc.example.com`,
    /// `default._bimi.example.com`): its TXT records, each one's character strings joined
    /// with nothing between them, none when it has none (NXDOMAIN too). For brand logos
    /// (`Engine::brand_logo`).
    fn txt(&self, name: String) -> std::result::Result<Vec<String>, DnsError>;
}

struct App(Arc<dyn DnsResolver>);

impl nimbra_core::dns::Resolver for App {
    fn mx(&self, domain: &str) -> anyhow::Result<Vec<(u16, String)>> {
        self.0
            .mx(domain.to_string())
            .map(|records| {
                records
                    .into_iter()
                    .map(|r| (r.preference, r.host))
                    .collect()
            })
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    fn txt(&self, name: &str) -> anyhow::Result<Vec<String>> {
        self.0
            .txt(name.to_string())
            .map_err(|error| anyhow::anyhow!("{error}"))
    }
}

/// From now on, the engine's MX and TXT lookups go to `resolver`. Once per process, before
/// the first `discover_servers` or `brand_logo`; the Mac's resolver is used when this is
/// never called.
/// Memory only.
#[uniffi::export]
pub fn use_dns_resolver(resolver: Arc<dyn DnsResolver>) -> Result<()> {
    nimbra_core::dns::set_resolver(Box::new(App(resolver)))
        .map_err(|error| NimbraError::invalid(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimbra_core::dns::Resolver as _;

    struct Fixed;

    impl DnsResolver for Fixed {
        fn mx(&self, domain: String) -> std::result::Result<Vec<MxRecord>, DnsError> {
            if domain == "example.org" {
                return Err(DnsError::Failed {
                    message: "timed out".into(),
                });
            }
            Ok(vec![MxRecord {
                preference: 10,
                host: format!("mx.{domain}"),
            }])
        }

        fn txt(&self, name: String) -> std::result::Result<Vec<String>, DnsError> {
            match name.as_str() {
                "_dmarc.example.com" => Ok(vec!["v=DMARC1; p=reject".into()]),
                "_dmarc.example.org" => Err(DnsError::Failed {
                    message: "timed out".into(),
                }),
                _ => Ok(Vec::new()),
            }
        }
    }

    #[test]
    fn the_apps_answers_and_failures_reach_the_engine() {
        let app = App(Arc::new(Fixed));
        assert_eq!(
            app.mx("example.com").unwrap(),
            [(10, "mx.example.com".to_string())]
        );
        assert!(app.mx("example.org").is_err());
        assert_eq!(
            app.txt("_dmarc.example.com").unwrap(),
            ["v=DMARC1; p=reject"]
        );
        assert!(app.txt("_dmarc.example.net").unwrap().is_empty());
        assert!(app.txt("_dmarc.example.org").is_err());
    }
}
