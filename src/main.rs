use clap::Parser;
use options::Options;

mod options;
mod handler;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let _options = Options::parse();
}
