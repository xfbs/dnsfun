# DNS Fun

Ever wondered how you can write a [DNS server](https://en.wikipedia.org/wiki/Domain_Name_System) in Rust? No? Well, too bad, I'm telling you anyways. But don't worry, this is going to be a fun one. 

Before we actually get started, I must perhaps first explain what DNS is. If you really want to understand it, I think you should check out Julia Evans' [DNS Zine](https://jvns.ca/blog/2022/04/26/new-zine--how-dns-works-/) post, she does a far better job at explaining it than I ever could. But if you don't have enough time, here's the TL;DR: 

> DNS is the protocol that is used to answer questions like *What's the [IP address](https://en.wikipedia.org/wiki/IP_address) of `google.com`*? Usually, when you open a website in your browser, you use domain names. In `https://dev.to`, the `dev.to` is a domain name. Other domain names you might know are `youtube.com` or `lobste.rs`. But in order for your browser (or any software on your computer, for that matter) to establish a connection, it needs to know which IP address to talk to. An IP address is something like `172.217.16.206`: basically just a few numbers that are enough to send your request to the right place. Very similar to a phone number or a physical address. Using the DNS protocol, your browser sends a request to get the IP addresses for some domain name, and then it gets a response with the answers.

If you are using Linux or macOS (or you have WSL2 enabled on your Windows 10 machine), you can use the DNS protocol to look up the IP addresses for `dev.to` using the `dig` tool:

```
$ dig +short dev.to
151.101.194.217
151.101.2.217
151.101.66.217
151.101.130.217
```

In this example, we are request the IPv4 address records of `dev.to`, but you can use the DNS protocol to query other stuff as well. We'll get to that in a bit.

## Setting up a new Rust project

> I'm writing this blog post as I'm writing this DNS server, and if you want to you can follow along, but all of the code also lives on [xfbs/dnsfun](https://github.com/xfbs/dnsfun) if you just want to clone it and try it out for yourself.

First, we must setup a new Rust project. Rust uses [cargo](https://doc.rust-lang.org/cargo/), a package manager, build system, documentation generation tool, and so much more. If you haven't set up Rust, check out the instructions at [rustup](https://rustup.rs/) to get started. We use the `cargo new` subcommand to create a new Rust project.

```
cargo new dnsfun
```

What this does is three things:

- Creates the folder `dnsfun`
- Creates a default code file at `dnsfun/src/main.rs`
- Creates a default config at `dnsfun/Cargo.toml`

## Adding dependencies

Once the project exists, we have to add dependencies. Usually, I add them one-by-one, when I need them. But for this project, I already know what I'm going to use, so I add the ones I know I will need upfront. 

Normally, we would add these dependencies manually to the `Crates.toml` file, but `cargo` has a helpful subcommand to help us do that.

```
cargo add clap --features derive,env
cargo add tokio --features macros,rt-multi-thread,net
cargo add trust-dns-server
cargo add tracing
cargo add tracing-subscriber
cargo add async-trait
```

What this does is add the dependencies to the `[dependencies]` section in the `Cargo.toml` file. The dependencies are:

- [tokio](https://docs.rs/tokio), a very powerful async library,
- [clap](https://docs.rs/clap), a library used to parse command-line options,
- [trust-dns-server](https://docs.rs/trust-dns-server), a library that implements a DNS server,
- [tracing](https://docs.rs/tracing), which lets us do logging and tracing of what's going on,
- [tracing-subscriber](https://docs.rs/tracing-subscriber), which lets us print logs and traces to the standard output,
- [async-trait](https://docs.rs/async-trait), which helps us create async trait methods,
- [anyhow](https://docs.rs/anyhow), a package that provides a generic error type,
- [thiserror](https://docs.rs/thiserror), a package that lets us easily define our own error types.

One thing you may have noticed is the features thing — in Rust, [dependencies often have optional features that are only built if requested](https://doc.rust-lang.org/cargo/reference/features.html). If you read the documentation for a crate, it will tell you which features you need to enable to use certain things. 

## Adding boilerplate code

With these dependencies in place, we can start with a very small boilerplate. Rust is not very verbose, it does not need some intricate setup or folder structure. Since we do want to use async, we need to initialize an async runtime, and because we want some amount of logging we need to initialize the tracing_subscriber crate. This is accomplished like this in the `src/main.rs` file.

```rust
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
}
```

The `#[tokio::main]` is a [macro from the tokio crate](https://docs.rs/tokio/latest/tokio/attr.main.html) that automatically generates the code needed to start the runtime. We can use this because we turned on the `macros` feature of tokio.

## Adding command-line options

There's some configuration options that the DNS server needs that we don't want to hard-code. So instead, we use command-line options to set them at runtime. We could have also used a configuration file, but that seemed overkill. So we create a new file, `src/options.rs`, with this content:

```rust
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
```

For explanation, the DNS protocol usually uses either UDP or TCP. Typically, UDP is preferred, but because there is a fixed maximum size for UDP packets, TCP can be used as fallback for when the response would be too large. We've declared three command-line options here:

- `--udp <socket>` sets the sockets (address and port to listen on) for UDP packets. If nothing is specified, it defaults to `0.0.0.0:1053`.
- `--tcp <socket>` sets the sockets to listen for TCP connections.
- `--domain <domain>` sets the domain that we want to serve DNS requests for, it defaults to `dnsfun.dev`.

The [clap](https://docs.rs/clap) crate with the `derive` feature is very neat: we have a full declarative command-line parser in only 20 or so lines of Rust. This is all made possible because of the `#[derive(Parser)]` -- this turns a Rust struct into a definition for command-line options. Any member of the field becomes a flag. If you add a field that is `Option<String>`, it becomes an optional flag. If you have a field that is a `Vec<String>`, you can pass it multiple times.

## Creating a dummy Request Handler

In order for us to serve DNS requests, we need some code that generates the response for each request. The crate that we are using, [trust-dns-server](https://docs.rs/trust-dns-server), calls this a [RequestHandler](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/trait.RequestHandler.html). 

We start by creating our own dummy implementation of a RequestHandler, just so we can get something to compile, and then we will get back to it and actually fill out the code.

We'll put this into a separate module, just to keep things somewhat tidy. So, we create a `src/handler.rs` with the following content:

```rust
use crate::Options;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {}

impl Handler {
    /// Create new handler from command-line options.
    pub fn from_options(_options: &Options) -> Self {
        Handler {}
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        _request: &Request,
        _response: R,
    ) -> ResponseInfo {
        todo!()
    }
}
```

I'll walk you through what is going on here. First, we are importing a few things, such as the `Options` struct that holds the command-line options and some types we need for the DNS server.

Next, we define a struct called `Handler` with a single member, `domain`. With the `#[derive(Clone, Debug)]`, we are asking the Rust compiler to implement [Clone](https://doc.rust-lang.org/std/clone/trait.Clone.html) for us, which gives us a `.clone()` method, and to implement [Debug](https://doc.rust-lang.org/std/fmt/trait.Debug.html), which generates code to let us pretty-print it for debugging purposes.

In the `impl Handler` block, we define a function to create a Handler struct from some parsed command-line options. If you are used to classes, this is equivalent to a constructor.

Finally, we implement the [RequestHandler](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/trait.RequestHandler.html) trait for our Handler struct. To implement a trait, we must to define all of the functions that the trait requires. If you are used to classes, you can think of traits like interfaces or abstract base classes. Any struct you create can implement as many traits as you like. You can also create your own traits and implement them for any structs you like, the system is very flexible.

Right now, [you cannot use async methods in trait methods in Rust](https://smallcultfollowing.com/babysteps/blog/2019/10/26/async-fn-in-traits-are-hard/), but the `#[async-trait::async-trait]` macro makes that possible still. This is a known quirk in the compiler, and the compiler itself will tell you to use [async-trait](https://docs.rs/async-trait) instead. Eventually, async methods in traits will be stabilized, but thanks to the powerful macro system we can polyfill that ourselves.

In the `handle_request` method, you can see that it is generic over `R`: it accepts anything that implements [ResponseHandler](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/trait.ResponseHandler.html). This is because sending out the response depends on the protocol being used (DNS can work over UDP, TCP, [TLS](https://en.wikipedia.org/wiki/DNS_over_TLS), [HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS), etc). So the actual response handler type will depend on which protocol the request came in on. Also, you can see that we've put a [`todo!()`](https://doc.rust-lang.org/std/macro.todo.html) where the implementation should be, this means that it will just crash because it is not implemented.

## Launching DNS Server

Now that we have a dummy [RequestHandler](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/trait.RequestHandler.html) in place, we can get back to the main method and actually start the DNS server. To do so, we change the `src/main.rs` to import the handler struct and create a [ServerFuture](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/struct.ServerFuture.html) with the right listeners and then await it:

```rust
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
        server.register_socket(UdpSocket::bind(udp).await?);
    }

    // register TCP listeners
    for tcp in &options.tcp {
        server.register_listener(TcpListener::bind(&tcp).await?, TCP_TIMEOUT);
    }

    // run DNS server
    server.block_until_done().await?;

    Ok(())
}
```

The first thing you might spot here is that we've defined a constant, `TCP_TIMEOUT`. This timeout is to prevent an attacker from creating a ton of TCP connections and then just letting them sit idle. It's good practice to give these constants a name so that we can add a [documentation comment](https://doc.rust-lang.org/rust-by-example/meta/doc.html) (starts with three slashes rather than two).

You can see how we are constructing a [ServerFuture](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/struct.ServerFuture.html), this is the DNS server. If you look at the documentation for the [`new` method](https://docs.rs/trust-dns-server/latest/trust_dns_server/struct.ServerFuture.html#method.new), you can see that it needs a handler which implements [RequestHandler](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/trait.RequestHandler.html). We have previously implemented that for our own `Handler`. So when we create the [ServerFuture](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/struct.ServerFuture.html), we have to pass it an instance of our Handler. This trait system makes software very composable.

We're also finally using the command-line options by registering the appropriate listeners. 

Another thing you might notice is that there is `.await` in some places but not in others. Any time we call an async functions, we have to `.await` it to get the result. But not all functions we call need to be async: [only those functions that might block at some point](https://rust-lang.github.io/async-book/01_getting_started/02_why_async.html). For example, opening a [UdpSocket](https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html) might block, because we have to wait for the operating system to give us a response, so that needs to be async. But creating a Handler struct from command-line options cannot block, because we have all the data we need (no need to wait for anything from disk). If this async stuff doesn't make sense to you right now, I might make a future blog post explaining it some more.

## Running the DNS server

At this point, we can already launch our DNS server. It is functional, except that any time we actually try to respond to a DNS packet, we will crash because of the `todo!()`. But that's okay, let's try it out!

We can use `cargo run -- <options>` to run it. The double dashes are needed to separate options for cargo run (before them) from options for the program (after them).

First, we can check out the automatically generated command-line options that we get from clap. If we pass the `--help` argument to our program, we will get a help text:

```
$ cargo run -- --help
Usage: dnsfun [OPTIONS]

Options:
  -u, --udp <UDP>        UDP socket to listen on [env: DNSFUN_UDP=] [default: 0.0.0.0:1053]
  -t, --tcp <TCP>        TCP socket to listen on [env: DNSFUN_TCP=]
  -d, --domain <DOMAIN>  Domain name [env: DNSFUN_DOMAIN=] [default: dnsfun.dev]
  -h, --help             Print help information
```

Sweet, it tells us what the flags are, what they mean (this is parsed from the documentation string in the `Options` struct), any default values and environment values that can be set.

To run our DNS server, we need two terminals. In the one terminal, we run the server itself. To get a better idea of what is going on, [we can set the `RUST_LOG` environment value to `trace`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/index.html#filtering-events-with-environment-variables), which turns on verbose logging of the tracing-subscriber. In the other terminal, we use `dig` to make a request to our DNS server. Here's what it looks like:

```
$ RUST_LOG=trace cargo run
2022-10-02T08:32:31.013539Z TRACE mio::poll: registering event source with poller: token=Token(0), interests=READABLE | WRITABLE    
2022-10-02T08:32:31.013657Z DEBUG trust_dns_server::server::server_future: registering udp: PollEvented { io: Some(UdpSocket { addr: 0.0.0.0:1053, fd: 6 }) }
2022-10-02T08:32:34.149745Z DEBUG trust_dns_server::server::server_future: received udp request from: 127.0.0.1:51997
2022-10-02T08:32:34.150111Z TRACE trust_dns_proto::rr::record_data: reading OPT
2022-10-02T08:32:34.150249Z DEBUG trust_dns_server::server::server_future: request:30324 src:UDP://127.0.0.1#51997 type:QUERY dnssec:false QUERY:test.com.:A:IN qflags:RD,AD
thread 'tokio-runtime-worker' panicked at 'not yet implemented', src/handler.rs:27:9
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

In the other terminal:

```
$ dig @127.0.0.1 -p 1053 test.com
```

So far, we can receive UDP DNS requests! But we obviously can't respond to them. We've gotten command-line parsing essentially for free with [clap](https://docs.rs/clap), gotten logging basically for free with [tracing_subscriber](https://docs.rs/tracing-subscriber), and a DNS server implementation for free from [trust-dns-server](https://docs.rs/trust-dns-server). Now comes the interesting part, where we fill in our request handler.

## Handling Requests, for real this time

Now, we have to implement our handle_request method to do something useful. There's a lot of funny things we could implement, but to keep this blog post somewhat short, there's three things I want to implement:

- `myip.dnsfun.dev` should return the IP address of whomever is querying it.
- `counter.dnsfun.dev` should return how many requests it has served so far.
- `<name>.hello.dnsfun.dev` should return a greeting for the name.

This part is perhaps the hardest part, the DNS protocol offers a lot of terminology and possibilities that might be confusing. If you feel confused at times, don't worry — so did I. 

The very first thing I need to do to make this possible is that we need to add some more fields to the `Handler` struct. To have a counter that is usable, we need some kind of atomic counter (it has to be atomic, because this whole thing is multithreaded). We will also need some help to route the requests for different subdomains.

```rust
/// DNS Request Handler
#[derive(Clone, Debug)]
pub struct Handler {
    /// Request counter, incremented on every successful request.
    pub counter: Arc<AtomicU64>,
    /// Domain to serve DNS responses for (requests for other domains are silently ignored).
    pub root_zone: LowerName,
    /// Zone name for counter (counter.dnsfun.dev)
    pub counter_zone: LowerName,
    /// Zone name for myip (myip.dnsfun.dev)
    pub myip_zone: LowerName,
    /// Zone name for hello (hello.dnsfun.dev)
    pub hello_zone: LowerName,
}
```

I've decided to use an [Arc\<AtomicU64\>](https://doc.rust-lang.org/std/sync/atomic/struct.AtomicU64.html) for my atomic counter. This is a variable that I can atomically increment and load from multiple threads. I also store the zone names in here, this is so I can easily check for a query if it matches anything I care about.

The [RequestHandler](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/trait.RequestHandler.html) trait wants the function to return a [ResponseInfo](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/struct.ResponseInfo.html), but there are cases where some error happens and we don't actually send a response. For this reason, I moved the actual logic into a different method, called `do_handle_request`, which I call in this handler. If that returns an error, I log it and fake a [ResponseInfo](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/struct.ResponseInfo.html).

```rust
#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        // try to handle request
        match self.do_handle_request(request, response).await {
            Ok(info) => info,
            Err(error) => {
                error!("Error in RequestHandler: {error}");
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
```

Next, in the `do_handle_response` method, which is just a private method of the `Handler` struct (similar to a private class method in OOP languages), I have to take a look at the request we got and decide what to do about it. 

```rust
impl Handler {
    /// Handle request, returning ResponseInfo if response was successfully sent, or an error.
    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, Error> {
        // make sure the request is a query
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }

        match request.query().name() {
            name if self.myip_zone.zone_of(name) => {
                self.do_handle_request_myip(request, response).await
            }
            name if self.counter_zone.zone_of(name) => {
                self.do_handle_request_counter(request, response).await
            }
            name if self.hello_zone.zone_of(name) => {
                self.do_handle_request_hello(request, response).await
            }
            name if self.root_zone.zone_of(name) => {
                self.do_handle_request_default(request, response).await
            }
            name => Err(Error::InvalidZone(name.clone())),
        }
    }
}
```

What you can see here is that I'm making sure that we are serving a query (it wouldn't make sense for us to respond to anything else). I have separate handlers for the different zones (subdomains) that I want to service, and I just try to find a match. For example, a lookup for `myip.dnsfun.dev` would match the `myip_zone`, so that would call the `do_handle_request_myip` handler. A lookup for `unknown.dnsfun.dev` would match the `root_zone`, so it would call the `do_handle_request_default` handler. If we get a request for `google.com`, which doesn't even match the root zone (`dnsfun.dev`), when we don't even issue a response at all.

```rust
impl Handler {
    /// Handle requests for myip.{domain}.
    async fn do_handle_request_myip<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = match request.src().ip() {
            IpAddr::V4(ipv4) => RData::A(ipv4),
            IpAddr::V6(ipv6) => RData::AAAA(ipv6),
        };
        let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }
}
```

Looking at the `do_handle_response_myip` handler, it shouldn't be too complicated: we increment the counter, then we build a response, and we use the [source IP of the request](https://docs.rs/trust-dns-server/0.22.0/trust_dns_server/server/struct.Request.html#method.src) to determine what to respond with.

```rust
impl Handler {
    /// Handle requests for counter.{domain}.
    async fn do_handle_request_counter<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![counter.to_string()]));
        let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }
}
```

The `do_handle_request_counter` is similarly simple: we [increment the counter](https://doc.rust-lang.org/std/sync/atomic/struct.AtomicU64.html#method.fetch_add), which returns the old value of it. Then we take that value, convert it to text and create a response with a text record.

```rust
impl Handler {
    /// Handle requests for *.hello.{domain}.
    async fn do_handle_request_hello<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let name: &Name = request.query().name().borrow();
        let zone_parts = (name.num_labels() - self.hello_zone.num_labels() - 1) as usize;
        let name = name
            .iter()
            .enumerate()
            .filter(|(i, _)| i <= &zone_parts)
            .fold(String::from("hello,"), |a, (_, b)| {
                a + " " + &String::from_utf8_lossy(b)
            });
        let rdata = RData::TXT(TXT::new(vec![name]));
        let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }
}
```

Finally, the `do_handle_request_hello` is a bit complicated, because we have to extract the name part from the query. For example, when you make a query for `patrick.hello.dnsfun.dev`, we return `hello, patrick`. So part of this complexity here is taking the query, splitting it into parts like `["patrick", "hello", "dnsfun", "dev"]`, and then chopping the last parts off, leaving `["patrick"]`, and then creating a string from that. That is what the iterators are doing here.

To get some nice error messages, we also create our own error type. This is something that [thiserror](https://docs.rs/thiserror) makes very easy, we can just create an enum and give it some information on how the errors should be displayed, and it takes care of the rest.

```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid OpCode {0:}")]
    InvalidOpCode(OpCode),
    #[error("Invalid MessageType {0:}")]
    InvalidMessageType(MessageType),
    #[error("Invalid Zone {0:}")]
    InvalidZone(LowerName),
    #[error("IO error: {0:}")]
    Io(#[from] std::io::Error),
}
```

## Trying out the DNS server

Again, we can run the server locally using `cargo run`. Running queries against it with `dig` shows that all of the features are working as expected:

```
$ dig +short @127.0.0.1 -p 1053 patrick.hello.dnsfun.dev
"hello, patrick"
$ dig +short @127.0.0.1 -p 1053 elon.musk.hello.dnsfun.dev
"hello, elon musk"
$ dig +short @127.0.0.1 -p 1053 counter.dnsfun.dev
"3"
$ dig +short @127.0.0.1 -p 1053 counter.dnsfun.dev
"4"
$ dig +short @127.0.0.1 -p 1053 myip.dnsfun.dev
127.0.0.1
```

## Containerizing the DNS Server

Now that we have built it, we need some way of deploying it. Since we are using Rust, we can simply build and deploy the binary, because it has no dependencies. But in the real world, that is not always the case. Maybe it needs some data at runtime, or it needs some specific libraries. Containerizing makes it possible to bundle it, along with all of the runtime data it needs, and deploy it anywhere.

We are using [Docker](https://en.wikipedia.org/wiki/Docker_(software)) to do this, so all we need to do is write a small [Dockerfile](https://docs.docker.com/engine/reference/builder/) to drop into the repository that tells Docker how to build the container for this service.

```docker
FROM rust AS builder

# copy code files
COPY Cargo.toml Cargo.lock /code/
COPY /src/ /code/src/

# build code
WORKDIR /code
RUN cargo build --release

# runtime container
FROM debian:11 AS runtime

# set default logging, can be overridden
ENV RUST_LOG=info

# copy binary
COPY --from=builder /code/target/release/dnsfun /usr/local/bin/dnsfun

# set entrypoint
ENTRYPOINT ["/usr/local/bin/dnsfun"]
```

This Dockerfile works in two stages: in the first stage, we use a `rust` image to build the service, resulting in a binary. In the next stage, we copy this binary into an empty `debian` container. Just for fun, we also add this to our `Cargo.toml` to make sure that the resulting binary is small:

```
[profile.release]
opt-level = "z"
lto = "thin"
debug = false
strip = true
```

What this does is tell the compiler to [optimize for small file size, perform some thin link-time optimisation, and strip debug symbols from the resulting binary](https://github.com/johnthagen/min-sized-rust). This results in a 2MB binary, there is certainly still a lot of room for making it smaller but this is good enough. 

## Automating the build

Normally, I prefer to use [GitLab](https://gitlab.com) and their CI system, but for this project we are using GitHub. What we want to achieve is that this project be compiled, the Docker container created and pushed to the [Docker Hub](https://hub.docker.com/) automatically on every push. We can do this with [GitHub Actions](https://github.com/features/actions).

We don't even have to come up with something on our own. We can just copy the sample configuration from the [actions-rs](https://github.com/actions-rs/meta/blob/master/recipes/quickstart.md) project to build and test the Rust code automatically, and the [sample config for Docker](https://github.com/marketplace/actions/build-and-push-docker-images).

The configuration files need to be placed inside the `.github/workflows/` folder.

## Deploying DNS-Fun

I went ahead and purchased the domain `dnsfun.dev` from [my registrar](https://inwx.de) for 19.99€, and I purchased a VPS from my [cloud provider](https://hetzner.com) for about 4.50€ per month. I then logged in to that VPS and ran something like this:

```
$ apt update
$ apt install docker.io apparmor-utils
$ docker run --name dnsfun -p 53:1053/udp xfbs/dnsfun --udp 0.0.0.0:1053
```

I had to do a few steps to get this VPS to be it's own nameserver -- I won't show you how it's done because it's different for every provider. But it's not too hard, you have to set some glue records and then update the nameserver settings. Piece of cake.

Now, you can make requests to it! You can either make requests through your normal DNS resolver, which meands that the responses are cached:

```
$ dig +short counter.dnsfun.dev TXT
"2140997"
$ dig +short mike.hello.dnsfun.dev TXT
"hello, mike"
```

Or, you can make request directly to it:

```
$ dig +short @159.69.35.198 counter.dnsfun.dev TXT
"2141001"
$ dig +short @159.69.35.198 myip.dnsfun.dev
123.23.45.67
```

I'm going to leave this thing running. Feel free to play around with it as you please. You can even try to break it, too. If you discover any issues, feel free to open up an issue on [GitHub](https://github.com/xfbs/dnsfun). If you have any fun ideas on what to implement, create a pull request. I will accept all of them and deploy them.

## Conclusion

I hope you enjoyed reading this blog post, it did turn out to be quite long. I wanted to walk you through the entire process of building and deploying this, without skipping over any parts.
