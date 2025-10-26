use std::{
    fmt::{self, Debug, Display},
    time::{Duration, Instant},
};

/// Helper to monitor throughput over fixed windows.
pub struct ThroughputMonitoring {
    throughput_duration: Duration,
    timer: Instant,
    current_throughput: u32,
    measured_throughput: Vec<ThroughputEntry>,
}

#[derive(Debug)]
struct ThroughputEntry {
    measured_throughput: u32,
    _start: Instant,
}

impl ThroughputEntry {
    fn new(measured_throughput: u32, time: Instant) -> ThroughputEntry {
        ThroughputEntry { measured_throughput, _start: time }
    }
}

impl ThroughputMonitoring {
    /// Creates a new throughput monitor with the specified window duration.
    pub fn new(throughput_duration: Duration) -> ThroughputMonitoring {
        ThroughputMonitoring {
            throughput_duration,
            timer: Instant::now(),
            current_throughput: 0,
            measured_throughput: Vec::new(),
        }
    }

    /// Records a tick and returns true if a measurement window completed.
    pub fn tick(&mut self) -> bool {
        if self.timer.elapsed() >= self.throughput_duration {
            self.measured_throughput
                .push(ThroughputEntry::new(self.current_throughput, self.timer));
            self.current_throughput = 0;
            self.timer = Instant::now();
            true
        } else {
            self.current_throughput += 1;
            false
        }
    }

    /// Returns the average throughput across all measurement windows.
    pub fn average(&self) -> u32 {
        if !self.measured_throughput.is_empty() {
            return self.measured_throughput.iter().map(|x| x.measured_throughput).sum::<u32>()
                / self.measured_throughput.len() as u32;
        }
        0
    }

    /// Resets all throughput measurements.
    pub fn reset(&mut self) {
        self.current_throughput = 0;
        self.measured_throughput.clear();
    }

    /// Returns the throughput from the most recent completed window.
    pub fn last_throughput(&self) -> u32 {
        self.measured_throughput.last().map(|x| x.measured_throughput).unwrap_or(0)
    }

    /// Returns the total number of ticks measured across all windows.
    pub fn total_measured_ticks(&self) -> u32 {
        self.measured_throughput.iter().map(|x| x.measured_throughput).sum::<u32>()
            + self.current_throughput
    }
}

impl Debug for ThroughputMonitoring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "Current Throughput: {}, Elapsed Time: {:#?}, Average Throughput: {}",
            self.last_throughput(),
            self.timer.elapsed(),
            self.average()
        )
    }
}

impl Display for ThroughputMonitoring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "Current Throughput: {}, Elapsed Time: {:#?}, Average Throughput: {}",
            self.last_throughput(),
            self.timer.elapsed(),
            self.average()
        )
    }
}
