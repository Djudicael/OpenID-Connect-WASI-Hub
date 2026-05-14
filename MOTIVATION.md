# Motivation

## Why Another OpenID Connect Implementation?

You might ask — *why build yet another OpenID provider when battle-tested solutions like Keycloak already exist?* And you would be completely right to ask.

### The WASI Bet

For the past few years, I have been building all my applications with WASI (WebAssembly System Interface) in mind. This is not a passing trend. The cost of cloud infrastructure is high and only keeps rising — compute, memory, orchestration overhead. WASI promises something different: lightweight, sandboxed, portable components that start fast, consume little, and run anywhere — from a container to bare metal to the edge — without the baggage of a full OS dependency graph.

Cloud providers aren't going to suddenly make infrastructure cheaper. But what if your application footprint was 100x smaller? What if you didn't need to provision a heavyweight runtime per service? That is the bet.

### The Solo Developer Reality

My goal was to avoid complex infrastructure. I am a solo developer. I did not want to reduce my standards — I still wanted high performance, strong security, and real scalability — but I needed to be pragmatic. I wanted to deploy my portfolio project ([djmxcreation_backend](https://github.com/Djudicael/djmxcreation_backend)) without drowning in orchestration complexity.

Artist and developer — what a combo to never finish a side project. But the landscape has changed, and the WASI ecosystem has matured enough to make this viable.

### The Ecosystem Gap

Many WASI initiatives exist, but most do not contribute enough practical value back to the ecosystem (in my view). Take Kubernetes: there is an initiative called [wasmCloud](https://wasmcloud.com/) that lets you run WebAssembly applications on Kubernetes. The issue? You have to **design your application around wasmCloud's conventions**. Your app stops being agnostic — you are now locked into their runtime assumptions.

I wanted something different: build a normal application once. Put it in a container and run it on Kubernetes, Nomad, Cloud Run, or whatever platform you choose. But also compile the exact same code to WASI and run it natively on a machine — **with zero code changes**. No special SDK wrappers. No runtime-specific API surface.

So, like any developer with a strong opinion, I started building my own platform: the **Wasm-Cloud-Platform**. The key design principle is runtime agnosticism — the application does not know or care where it runs.

### The Hardest Problem: Database Connectivity

Classical applications rely heavily on OS-level libraries — filesystem, networking, system clocks — most of which are not available under WASI Preview 2. And even when WASI provides equivalents, the library ecosystem hasn't caught up: most Rust crates assume `std::net::TcpStream` or link against OpenSSL, neither of which compile to `wasm32-wasip2`.

This hit hardest with database connectivity. I went all-in on PostgreSQL — but there was no PostgreSQL client library that worked under WASI. I tried adapting existing Rust-based OpenID providers. Even with Rust's ecosystem being more WASM-friendly than most languages, the modifications needed were enormous. Every dependency chain that touched the network layer had to be rewritten.

Eventually, I accepted that adapting an existing project was not practical. Starting from scratch was the faster path — and the better one, because it meant every design decision could be evaluated through the lens of WASI compatibility from day one.

### Building the Foundation

Before I could build the OpenID provider, I needed a PostgreSQL client. So I wrote [pg_client](https://github.com/Djudicael/pg_client) — a pure-Rust, WASI-compatible PostgreSQL driver implementing the wire protocol directly. It may not be the most feature-complete Postgres driver in the world, but it is complete enough for the needs of a production identity provider: parameterized queries, transactions, connection pooling, and TLS.

With that foundation in place, the OpenID Connect WASI Hub was built top to bottom:

- **Pure domain logic** with zero I/O, zero framework dependencies
- **Pure-Rust cryptography** — no OpenSSL, no system libraries, just `argon2`, `rsa`, `sha2`, and `rustls`
- **PostgreSQL only** — no filesystem state, no embedded databases, no local storage
- **Dual entry point** — compiles to both native binary (`#[tokio::main]`) and WASI component (`#[wstd_axum::http_server]`) from the same codebase

### The Bottom Line

This project exists because:

1. Infrastructure costs are not going down, and WASI is the most credible path to reducing them without sacrificing capability.
2. No existing OpenID provider works under WASI without massive, invasive modifications.
3. Building WASI-first from scratch produced a cleaner, more portable architecture than retrofitting would have.
4. The WASI ecosystem needs more practical, production-grade examples — not just "hello world" demos — to prove the model works.

If you are reading this and thinking about building for WASI: it is harder today, but the constraints force better design. And once you ship, you can deploy anywhere.
