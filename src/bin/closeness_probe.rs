//! Closeness lookup probe.
//!
//! Joins a saorsa-core network as a passive DHT participant, then loops
//! issuing `find_closest_nodes_network` calls against random 32-byte targets
//! and reports per-call latency and how many peers each lookup returned.
//!
//! Built to diagnose why `PaymentVerifier::verify_merkle_candidate_closeness`
//! sees its iterative DHT lookup time out at 60 s on STG-01 even though node
//! CPU is well below saturation. Use the baseline numbers from this harness
//! to tell "the lookup itself is slow on this network" apart from
//! "verifier-side lookups are slow only when contended by chunk-PUT
//! handlers" — this binary does only the former.
//!
//! ## CLI
//!
//! ```text
//! closeness-probe --bootstrap 1.2.3.4:10000 --bootstrap 5.6.7.8:10000 \
//!     [--iterations 30] [--count 16] [--warmup-secs 30] [--sleep-secs 1]
//! ```
//!
//! Multiple `--bootstrap` flags accumulate. All other flags optional.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rand::RngCore;
use saorsa_core::{IPDiversityConfig, MultiAddr, NodeConfig, NodeMode, P2PNode};
use tracing_subscriber::EnvFilter;

const DEFAULT_ITERATIONS: usize = 30;
const DEFAULT_COUNT: usize = 16;
const DEFAULT_WARMUP_SECS: u64 = 30;
const DEFAULT_SLEEP_SECS: u64 = 1;

struct Args {
    bootstraps: Vec<SocketAddr>,
    iterations: usize,
    count: usize,
    warmup_secs: u64,
    sleep_secs: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut bootstraps: Vec<SocketAddr> = Vec::new();
    let mut iterations = DEFAULT_ITERATIONS;
    let mut count = DEFAULT_COUNT;
    let mut warmup_secs = DEFAULT_WARMUP_SECS;
    let mut sleep_secs = DEFAULT_SLEEP_SECS;

    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--bootstrap" => {
                let v = argv
                    .next()
                    .ok_or_else(|| "--bootstrap needs a host:port".to_string())?;
                let addr: SocketAddr = v
                    .parse()
                    .map_err(|e| format!("--bootstrap {v}: {e}"))?;
                bootstraps.push(addr);
            }
            "--iterations" => {
                iterations = argv
                    .next()
                    .ok_or_else(|| "--iterations needs a number".to_string())?
                    .parse()
                    .map_err(|e| format!("--iterations: {e}"))?;
            }
            "--count" => {
                count = argv
                    .next()
                    .ok_or_else(|| "--count needs a number".to_string())?
                    .parse()
                    .map_err(|e| format!("--count: {e}"))?;
            }
            "--warmup-secs" => {
                warmup_secs = argv
                    .next()
                    .ok_or_else(|| "--warmup-secs needs a number".to_string())?
                    .parse()
                    .map_err(|e| format!("--warmup-secs: {e}"))?;
            }
            "--sleep-secs" => {
                sleep_secs = argv
                    .next()
                    .ok_or_else(|| "--sleep-secs needs a number".to_string())?
                    .parse()
                    .map_err(|e| format!("--sleep-secs: {e}"))?;
            }
            "-h" | "--help" => {
                return Err(String::from("see header comment"));
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }

    if bootstraps.is_empty() {
        return Err("at least one --bootstrap is required".to_string());
    }

    Ok(Args {
        bootstraps,
        iterations,
        count,
        warmup_secs,
        sleep_secs,
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // INFO is loud enough to surface saorsa-core's existing per-iteration
    // logs in dht_network_manager, which is the data we're after.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .try_init();

    println!(
        "[probe] bootstraps={:?} iterations={} count={} warmup={}s sleep={}s",
        args.bootstraps, args.iterations, args.count, args.warmup_secs, args.sleep_secs,
    );

    let mut config = match NodeConfig::builder()
        .port(0)
        .ipv6(true)
        .local(false)
        .mode(NodeMode::Client)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error building NodeConfig: {e}");
            return ExitCode::FAILURE;
        }
    };
    config.diversity_config = Some(IPDiversityConfig::permissive());
    config.bootstrap_peers = args
        .bootstraps
        .iter()
        .map(|a| MultiAddr::quic(*a))
        .collect();

    let node = match P2PNode::new(config).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error creating P2PNode: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = node.start().await {
        eprintln!("error starting P2PNode: {e}");
        return ExitCode::FAILURE;
    }

    println!("[probe] node started, peer_id={}", node.peer_id().to_hex());
    println!(
        "[probe] warming up for {}s before first lookup",
        args.warmup_secs
    );
    tokio::time::sleep(Duration::from_secs(args.warmup_secs)).await;

    let connected = node.connected_peers().await.len();
    println!("[probe] {connected} peers connected after warmup");

    let mut latencies_ms: Vec<u128> = Vec::with_capacity(args.iterations);
    let mut returned_counts: Vec<usize> = Vec::with_capacity(args.iterations);
    let mut errors: usize = 0;

    for i in 0..args.iterations {
        let mut target = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut target);

        let started = Instant::now();
        let result = node.dht().find_closest_nodes(&target, args.count).await;
        let elapsed = started.elapsed();
        let elapsed_ms = elapsed.as_millis();

        match result {
            Ok(nodes) => {
                latencies_ms.push(elapsed_ms);
                returned_counts.push(nodes.len());
                let prefixes: Vec<String> = nodes
                    .iter()
                    .take(4)
                    .map(|n| {
                        let h = n.peer_id.to_hex();
                        h[..8.min(h.len())].to_string()
                    })
                    .collect();
                println!(
                    "[probe {:>3}/{}] target={} elapsed={:>7}ms returned={:>2}/{} closest={:?}",
                    i + 1,
                    args.iterations,
                    hex_short(&target),
                    elapsed_ms,
                    nodes.len(),
                    args.count,
                    prefixes,
                );
            }
            Err(e) => {
                errors += 1;
                println!(
                    "[probe {:>3}/{}] target={} ERROR after {}ms: {e}",
                    i + 1,
                    args.iterations,
                    hex_short(&target),
                    elapsed_ms,
                );
            }
        }

        if i + 1 < args.iterations {
            tokio::time::sleep(Duration::from_secs(args.sleep_secs)).await;
        }
    }

    println!();
    println!(
        "=== summary: {} successful, {} errors ===",
        latencies_ms.len(),
        errors,
    );

    if latencies_ms.is_empty() {
        return ExitCode::FAILURE;
    }

    let mut sorted = latencies_ms.clone();
    sorted.sort_unstable();
    let pick = |p: usize| sorted[(sorted.len() * p / 100).min(sorted.len() - 1)];
    let mean: u128 = latencies_ms.iter().sum::<u128>() / latencies_ms.len() as u128;

    println!(
        "elapsed ms — min={} p50={} mean={} p90={} p95={} p99={} max={}",
        sorted[0],
        pick(50),
        mean,
        pick(90),
        pick(95),
        pick(99),
        sorted[sorted.len() - 1],
    );

    let avg_returned = returned_counts.iter().sum::<usize>() as f64 / returned_counts.len() as f64;
    let short_runs = returned_counts.iter().filter(|&&c| c < args.count).count();
    println!(
        "peers returned — mean={:.1} of {} requested; short results = {}/{}",
        avg_returned,
        args.count,
        short_runs,
        returned_counts.len(),
    );

    ExitCode::SUCCESS
}

fn hex_short(target: &[u8; 32]) -> String {
    let mut s = String::with_capacity(10);
    for b in &target[..4] {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s.push_str("…");
    s
}
