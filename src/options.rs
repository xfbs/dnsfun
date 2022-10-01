use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Clone, Debug)]
pub struct Options {
    /// UDP socket to listen on.
    #[clap(long, short, default_value = "0.0.0.0:1053", env = "DNSFUN_UDP")]
    pub udp: Vec<SocketAddr>,

    /// TCP socket to listen on.
    #[clap(long, short, env = "DNSFUN_TCP")]
    pub tcp: Vec<SocketAddr>,

    /// Domain name
    #[clap(long, short, default_value = "dnsfun.dev", env = "DNSFUN_DOMAIN")]
    pub domain: String,
}
