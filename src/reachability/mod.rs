// Copyright 2024 Saorsa Labs Limited
//
// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! # Canary-gated relay acquisition
//!
//! Every non-client node tries to acquire a MASQUE relay from an XOR-closest
//! peer after bootstrap. Once a candidate accepts, the driver asks
//! independent randomized non-close witnesses to cold-dial the relay-allocated
//! address and confirm this node's authenticated identity before the address
//! is published to the DHT.
//!
//! ## Module layout
//!
//! - [`acquisition`]: the reusable XOR-closest [`RelayAcquisition`]
//!   coordinator. Pure logic — wraps a [`RelaySessionEstablisher`] trait so
//!   the walk can be unit-tested with mock establishers.
//! - [`canary`]: internal request/response protocol and quorum check used
//!   to verify a freshly acquired relay from third-party vantage points.
//! - [`session`]: the [`run_relay_acquisition`] entry point. Builds the
//!   filtered candidate list from the routing table and hands it to the
//!   coordinator.
//! - [`driver`]: the [`spawn_acquisition_driver`] background task. Owns
//!   every state transition for this node's relay: initial acquisition,
//!   backoff retry, K-closest-eviction watch, tunnel-health poll, and
//!   the republish-then-reacquire sequence on loss.

pub(crate) mod acquisition;
pub(crate) mod canary;
pub(crate) mod driver;
pub(crate) mod session;

pub(crate) use acquisition::{RelaySessionEstablishError, RelaySessionEstablisher};
pub(crate) use driver::spawn_acquisition_driver;

#[cfg(test)]
pub(crate) mod test_logs {
    //! Captures formatted INFO+ events, the levels production ships to the
    //! fleet log store, so tests can check what a log line names.

    use std::io;
    use std::sync::{Arc, Mutex};

    use tracing::Level;
    use tracing::subscriber::DefaultGuard;

    #[derive(Clone, Default)]
    pub(crate) struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl CapturedLogs {
        /// Route this thread's INFO+ events here until the guard drops.
        pub(crate) fn capture(&self) -> DefaultGuard {
            let logs = self.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                // A timestamp's digits could match a port a test looks for.
                .without_time()
                .with_max_level(Level::INFO)
                .with_writer(move || logs.clone())
                .finish();
            tracing::subscriber::set_default(subscriber)
        }

        pub(crate) fn text(&self) -> String {
            self.0
                .lock()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default()
        }

        pub(crate) fn lines_containing(&self, needle: &str) -> Vec<String> {
            self.text()
                .lines()
                .filter(|line| line.contains(needle))
                .map(str::to_owned)
                .collect()
        }
    }

    impl io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut bytes = self
                .0
                .lock()
                .map_err(|_| io::Error::other("captured log buffer poisoned"))?;
            bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
