use anyhow::Result;
use clap::Parser;
use handler::Handler;
use options::Options;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;

mod handler;
mod options;

/// Timeout for TCP connections.
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let options = Options::parse();
    let handler = Handler::from_options(&options);

    // create DNS server
    let mut server = ServerFuture::new(handler);

    // register UDP listeners
    for udp in &options.udp {
        server.register_socket(UdpSocket::bind(&udp).await?);
    }

    // register TCP listeners
    for tcp in &options.tcp {
        server.register_listener(TcpListener::bind(&tcp).await?, TCP_TIMEOUT);
    }

    // run DNS server
    server.block_until_done().await?;

    Ok(())
}
