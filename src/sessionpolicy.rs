use connectionsignature::ConnectionSignature;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SessionPolicy {
}

impl SessionPolicy {
    pub fn new() -> SessionPolicy {
        SessionPolicy {}
    }

    // Tests if a signature is suitable for our current policy
    pub fn suitable_connection(&self, _: &ConnectionSignature) -> bool {
        true
    }
}
