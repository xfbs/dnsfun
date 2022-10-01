use clap::Parser;
use options::Options;

mod options;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let _options = Options::parse();
}
