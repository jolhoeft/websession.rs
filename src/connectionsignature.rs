#[cfg(feature = "hyper")]
extern crate hyper;

#[cfg(feature = "hyper")]
use hyper::server::request::Request;

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionSignature;

impl ConnectionSignature {
    pub fn new() -> ConnectionSignature {
        ConnectionSignature
    }

    #[cfg(feature = "hyper")]
    pub fn new_hyper(_: &Request) -> ConnectionSignature {
        // stubbed in
        ConnectionSignature
    }
}

