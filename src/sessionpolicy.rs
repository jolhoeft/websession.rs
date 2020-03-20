#![forbid(unsafe_code)]

use connectionsignature::ConnectionSignature;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SessionPolicy {
    pub salt: String,
}

impl SessionPolicy {
    pub fn new(salt: &str) -> SessionPolicy {
        SessionPolicy {
            salt: salt.to_string(),
        }
    }

    // Tests if a signature is suitable for our current policy
    pub fn suitable_connection(&self, _: &ConnectionSignature) -> bool {
        true
    }
}
