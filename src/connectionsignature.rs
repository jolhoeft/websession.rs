#[cfg(feature = "hyper")]
extern crate hyper;

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionSignature;

impl ConnectionSignature {
    pub fn new() -> ConnectionSignature {
        ConnectionSignature
    }

    #[cfg(feature = "hyper")]
    pub fn new_hyper(req: &Request) -> ConnectionSignature {
        // stubbed in
        ConnectionSignature
    }
}

