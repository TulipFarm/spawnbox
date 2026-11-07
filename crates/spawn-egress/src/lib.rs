//! The egress proxy every sandbox TCP connection goes through, and the DNS
//! forwarder every sandbox query goes through. They check the sandbox's
//! egress policy, log each connection and query, and add secret values to
//! HTTPS requests for the hosts a secret allows.

pub mod policy;
pub mod secrets;
pub mod sniff;
pub mod tls;

#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod proxy;

pub use policy::{Mode, Policy};
#[cfg(target_os = "linux")]
pub use proxy::{Activity, Egress, Registration, Sink};
pub use secrets::{Attached, Kind, Secret, SecretStore};
pub use tls::Ca;
