use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE};
use crate::virtio::{DeviceQueue, InterruptTransport};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::{FrontendError, RxError, TxError, VirtioNetBackend};
use super::VNET_HDR_LEN;

#[cfg(target_os = "macos")]
use std::os::fd::RawFd;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::thread;
use std::time::Instant;
use std::{cmp, result};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const VMNET_TX_PROFILE_INTERVAL_BYTES: u64 = 16 * 1024 * 1024;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

#[derive(Default, Copy, Clone)]
struct PacketSummary {
    tcp: bool,
    tcp_payload_bytes: usize,
    tcp_ack_only: bool,
}

fn read_be_u16(data: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = data.get(..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn read_le_u16(data: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = data.get(..2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn summarize_packet(frame: &[u8]) -> PacketSummary {
    const ETHERTYPE_IPV4: u16 = 0x0800;
    const ETHERTYPE_IPV6: u16 = 0x86dd;
    const ETHERTYPE_VLAN: u16 = 0x8100;
    const ETHERTYPE_QINQ: u16 = 0x88a8;
    const IPPROTO_TCP: u8 = 6;
    const TCP_FIN: u8 = 0x01;
    const TCP_SYN: u8 = 0x02;
    const TCP_RST: u8 = 0x04;
    const TCP_ACK: u8 = 0x10;

    if frame.len() < 14 {
        return PacketSummary::default();
    }

    let mut l3_offset = 14usize;
    let Some(mut ether_type) = read_be_u16(&frame[12..]) else {
        return PacketSummary::default();
    };
    for _ in 0..2 {
        if ether_type != ETHERTYPE_VLAN && ether_type != ETHERTYPE_QINQ {
            break;
        }
        if frame.len() < l3_offset + 4 {
            return PacketSummary::default();
        }
        let Some(next_type) = read_be_u16(&frame[l3_offset + 2..]) else {
            return PacketSummary::default();
        };
        ether_type = next_type;
        l3_offset += 4;
    }

    let (tcp_offset, tcp_length) = match ether_type {
        ETHERTYPE_IPV4 => {
            if frame.len() < l3_offset + 20 {
                return PacketSummary::default();
            }
            let ihl = usize::from(frame[l3_offset] & 0x0f) * 4;
            if ihl < 20 || frame.len() < l3_offset + ihl || frame[l3_offset + 9] != IPPROTO_TCP {
                return PacketSummary::default();
            }
            let Some(total_length) = read_be_u16(&frame[l3_offset + 2..]) else {
                return PacketSummary::default();
            };
            let Some(fragment) = read_be_u16(&frame[l3_offset + 6..]) else {
                return PacketSummary::default();
            };
            if fragment & 0x1fff != 0 {
                return PacketSummary::default();
            }
            let total_length = usize::from(total_length).min(frame.len() - l3_offset);
            if total_length < ihl {
                return PacketSummary::default();
            }
            (l3_offset + ihl, total_length - ihl)
        }
        ETHERTYPE_IPV6 => {
            if frame.len() < l3_offset + 40 || frame[l3_offset + 6] != IPPROTO_TCP {
                return PacketSummary::default();
            }
            let Some(payload_length) = read_be_u16(&frame[l3_offset + 4..]) else {
                return PacketSummary::default();
            };
            let tcp_offset = l3_offset + 40;
            let tcp_length = usize::from(payload_length).min(frame.len().saturating_sub(tcp_offset));
            (tcp_offset, tcp_length)
        }
        _ => return PacketSummary::default(),
    };

    if tcp_length < 20 || frame.len() < tcp_offset + 20 {
        return PacketSummary::default();
    }
    let tcp_header_length = usize::from(frame[tcp_offset + 12] >> 4) * 4;
    if tcp_header_length < 20 || tcp_header_length > tcp_length {
        return PacketSummary::default();
    }
    let flags = frame[tcp_offset + 13];
    let tcp_payload_bytes = tcp_length - tcp_header_length;
    let tcp_ack_only = flags & TCP_ACK != 0
        && flags & (TCP_FIN | TCP_SYN | TCP_RST) == 0
        && tcp_payload_bytes == 0;
    PacketSummary {
        tcp: true,
        tcp_payload_bytes,
        tcp_ack_only,
    }
}

#[derive(Default)]
struct TxProfile {
    enabled: bool,
    sample: u64,
    bytes: u64,
    sample_started_at: Option<Instant>,

    epoll_wait_calls: u64,
    epoll_wait_ns: u128,
    epoll_wait_max_ns: u128,
    epoll_batches: u64,
    epoll_events: u64,

    queue_events: u64,
    queue_event_reads: u64,
    queue_event_value_sum: u64,
    queue_event_value_max: u64,
    queue_event_gap_samples: u64,
    queue_event_gap_ns: u128,
    queue_event_gap_max_ns: u128,
    queue_event_gap_over_100us: u64,
    queue_event_gap_over_250us: u64,
    queue_event_gap_over_500us: u64,
    queue_event_gap_over_1ms: u64,
    ack_to_tx_samples: u64,
    ack_to_tx_ns: u128,
    ack_to_tx_max_ns: u128,
    ack_to_tx_over_100us: u64,
    ack_to_tx_over_250us: u64,
    ack_to_tx_over_500us: u64,
    ack_to_tx_over_1ms: u64,
    last_tx_data_to_ack_samples: u64,
    last_tx_data_to_ack_ns: u128,
    last_tx_data_to_ack_max_ns: u128,

    timer_events: u64,
    backend_writable_events: u64,
    tx_loop_calls: u64,
    tx_loop_ns: u128,
    process_tx_calls: u64,
    process_tx_ns: u128,
    descriptor_chains: u64,
    descriptors: u64,
    guest_read_calls: u64,
    guest_read_ns: u128,
    backend_write_calls: u64,
    backend_write_ns: u128,
    flush_calls: u64,
    flush_ns: u128,
    deferred_stalls: u64,
    notification_enable_calls: u64,
    notification_races: u64,
    completion_batches: u64,
    add_used_calls: u64,
    add_used_ns: u128,
    irq_signals: u64,
    irq_suppressed: u64,
    irq_signal_ns: u128,
    completion_to_irq_samples: u64,
    completion_to_irq_ns: u128,
    completion_to_irq_max_ns: u128,
    max_chains_per_process_tx: u64,

    tx_frame_bytes: u64,
    tx_frame_min: u64,
    tx_frame_max: u64,
    tx_tcp_frames: u64,
    tx_tcp_data_frames: u64,
    tx_tcp_payload_bytes: u64,
    tx_csum_needed: u64,
    tx_gso_none: u64,
    tx_gso_tcpv4: u64,
    tx_gso_tcpv6: u64,
    tx_gso_other: u64,
    tx_gso_size_max: u64,

    rx_queue_events: u64,
    rx_backend_events: u64,
    process_rx_calls: u64,
    process_rx_ns: u128,
    backend_read_calls: u64,
    backend_read_empty: u64,
    backend_read_ns: u128,
    guest_write_calls: u64,
    guest_write_ns: u128,
    rx_frames: u64,
    rx_bytes: u64,
    rx_tcp_frames: u64,
    rx_tcp_ack_only: u64,
    rx_tcp_payload_frames: u64,
    rx_tcp_payload_bytes: u64,
    rx_irq_signals: u64,
    rx_irq_signal_ns: u128,
    rx_deferred_frames: u64,
    ack_interarrival_samples: u64,
    ack_interarrival_ns: u128,
    ack_interarrival_max_ns: u128,
    ack_interarrival_over_100us: u64,
    ack_interarrival_over_250us: u64,
    ack_interarrival_over_500us: u64,
    ack_interarrival_over_1ms: u64,
    ack_backend_to_guest_samples: u64,
    ack_backend_to_guest_ns: u128,
    ack_backend_to_guest_max_ns: u128,
    ack_to_irq_samples: u64,
    ack_to_irq_ns: u128,
    ack_to_irq_max_ns: u128,
}

impl TxProfile {
    fn new(enabled: bool) -> Self {
        Self { enabled, ..Self::default() }
    }

    fn add_elapsed(total: &mut u128, started: Instant) -> u128 {
        let elapsed = started.elapsed().as_nanos();
        *total += elapsed;
        elapsed
    }

    fn record_thresholds(
        ns: u128,
        over_100us: &mut u64,
        over_250us: &mut u64,
        over_500us: &mut u64,
        over_1ms: &mut u64,
    ) {
        if ns >= 100_000 {
            *over_100us += 1;
        }
        if ns >= 250_000 {
            *over_250us += 1;
        }
        if ns >= 500_000 {
            *over_500us += 1;
        }
        if ns >= 1_000_000 {
            *over_1ms += 1;
        }
    }

    fn record_queue_event_gap(&mut self, ns: u128) {
        self.queue_event_gap_samples += 1;
        self.queue_event_gap_ns += ns;
        self.queue_event_gap_max_ns = self.queue_event_gap_max_ns.max(ns);
        Self::record_thresholds(
            ns,
            &mut self.queue_event_gap_over_100us,
            &mut self.queue_event_gap_over_250us,
            &mut self.queue_event_gap_over_500us,
            &mut self.queue_event_gap_over_1ms,
        );
    }

    fn record_ack_to_tx(&mut self, ns: u128) {
        self.ack_to_tx_samples += 1;
        self.ack_to_tx_ns += ns;
        self.ack_to_tx_max_ns = self.ack_to_tx_max_ns.max(ns);
        Self::record_thresholds(
            ns,
            &mut self.ack_to_tx_over_100us,
            &mut self.ack_to_tx_over_250us,
            &mut self.ack_to_tx_over_500us,
            &mut self.ack_to_tx_over_1ms,
        );
    }

    fn record_ack_interarrival(&mut self, ns: u128) {
        self.ack_interarrival_samples += 1;
        self.ack_interarrival_ns += ns;
        self.ack_interarrival_max_ns = self.ack_interarrival_max_ns.max(ns);
        Self::record_thresholds(
            ns,
            &mut self.ack_interarrival_over_100us,
            &mut self.ack_interarrival_over_250us,
            &mut self.ack_interarrival_over_500us,
            &mut self.ack_interarrival_over_1ms,
        );
    }

    fn record_ack_backend_to_guest(&mut self, ns: u128) {
        self.ack_backend_to_guest_samples += 1;
        self.ack_backend_to_guest_ns += ns;
        self.ack_backend_to_guest_max_ns = self.ack_backend_to_guest_max_ns.max(ns);
    }

    fn record_ack_to_irq(&mut self, ns: u128) {
        self.ack_to_irq_samples += 1;
        self.ack_to_irq_ns += ns;
        self.ack_to_irq_max_ns = self.ack_to_irq_max_ns.max(ns);
    }

    fn record_tx_frame(&mut self, frame: &[u8]) -> (PacketSummary, bool) {
        let network = frame.get(VNET_HDR_LEN..).unwrap_or(&[]);
        let summary = summarize_packet(network);

        // Ignore startup/background traffic and begin each diagnostic sample on
        // the first TCP data frame. Resetting here also discards idle epoll time
        // accumulated between 16 MiB uploads, which otherwise dominates the
        // first sample and obscures queue/ACK pacing inside the transfer itself.
        let started_sample = self.sample_started_at.is_none() && summary.tcp_payload_bytes > 0;
        if started_sample {
            let enabled = self.enabled;
            let sample = self.sample;
            *self = Self::new(enabled);
            self.sample = sample;
            self.sample_started_at = Some(Instant::now());
        }
        if self.sample_started_at.is_none() {
            return (summary, false);
        }

        self.bytes += frame.len() as u64;
        let network_len = network.len() as u64;
        self.tx_frame_bytes += network_len;
        if self.tx_frame_min == 0 || network_len < self.tx_frame_min {
            self.tx_frame_min = network_len;
        }
        self.tx_frame_max = self.tx_frame_max.max(network_len);

        if frame.len() >= VNET_HDR_LEN {
            if frame[0] & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
                self.tx_csum_needed += 1;
            }
            let gso_type = frame[1] & 0x7f;
            match gso_type {
                VIRTIO_NET_HDR_GSO_NONE => self.tx_gso_none += 1,
                VIRTIO_NET_HDR_GSO_TCPV4 => self.tx_gso_tcpv4 += 1,
                VIRTIO_NET_HDR_GSO_TCPV6 => self.tx_gso_tcpv6 += 1,
                _ => self.tx_gso_other += 1,
            }
            if let Some(gso_size) = read_le_u16(&frame[4..]) {
                self.tx_gso_size_max = self.tx_gso_size_max.max(u64::from(gso_size));
            }
        }

        if summary.tcp {
            self.tx_tcp_frames += 1;
            if summary.tcp_payload_bytes > 0 {
                self.tx_tcp_data_frames += 1;
                self.tx_tcp_payload_bytes += summary.tcp_payload_bytes as u64;
            }
        }
        (summary, started_sample)
    }

    fn record_rx_delivery(&mut self, frame: &[u8]) -> PacketSummary {
        let network = frame.get(VNET_HDR_LEN..).unwrap_or(&[]);
        self.rx_frames += 1;
        self.rx_bytes += network.len() as u64;
        let summary = summarize_packet(network);
        if summary.tcp {
            self.rx_tcp_frames += 1;
            if summary.tcp_ack_only {
                self.rx_tcp_ack_only += 1;
            }
            if summary.tcp_payload_bytes > 0 {
                self.rx_tcp_payload_frames += 1;
                self.rx_tcp_payload_bytes += summary.tcp_payload_bytes as u64;
            }
        }
        summary
    }

    fn average_us(total_ns: u128, samples: u64) -> f64 {
        if samples == 0 {
            0.0
        } else {
            total_ns as f64 / samples as f64 / 1_000.0
        }
    }

    fn maybe_print(&mut self) -> bool {
        if !self.enabled || self.tx_tcp_payload_bytes < VMNET_TX_PROFILE_INTERVAL_BYTES {
            return false;
        }

        let chains_per_process_tx = if self.process_tx_calls == 0 {
            0.0
        } else {
            self.descriptor_chains as f64 / self.process_tx_calls as f64
        };
        let descriptors_per_chain = if self.descriptor_chains == 0 {
            0.0
        } else {
            self.descriptors as f64 / self.descriptor_chains as f64
        };
        let wall_ms = self
            .sample_started_at
            .map(|started| started.elapsed().as_secs_f64() * 1_000.0)
            .unwrap_or(0.0);

        eprintln!(
            "libkrun: virtio-net tx profile sample={} bytes={} wall_ms={:.3} epoll_wait_calls={} \
epoll_wait_ms={:.3} epoll_wait_max_ms={:.3} epoll_batches={} epoll_events={} queue_events={} \
queue_event_reads={} queue_event_value_sum={} queue_event_value_max={} queue_gap_avg_us={:.3} \
queue_gap_max_us={:.3} queue_gap_ge_100us={} queue_gap_ge_250us={} queue_gap_ge_500us={} \
queue_gap_ge_1ms={} timer_events={} backend_writable_events={} tx_loop_calls={} tx_loop_ms={:.3} \
process_tx_calls={} process_tx_ms={:.3} descriptor_chains={} descriptors={} chains_per_process_tx={:.3} \
descriptors_per_chain={:.3} max_chains_per_process_tx={} guest_read_calls={} guest_read_ms={:.3} \
backend_write_calls={} backend_write_ms={:.3} flush_calls={} flush_ms={:.3} deferred_stalls={} \
notification_enable_calls={} notification_races={} completion_batches={} add_used_calls={} add_used_ms={:.3} \
irq_signals={} irq_suppressed={} irq_signal_ms={:.3} completion_to_irq_samples={} \
completion_to_irq_avg_us={:.3} completion_to_irq_max_us={:.3} tx_frame_bytes={} tx_frame_min={} tx_frame_max={} tx_tcp_frames={} \
tx_tcp_data_frames={} tx_tcp_payload_bytes={} tx_csum_needed={} tx_gso_none={} tx_gso_tcpv4={} \
tx_gso_tcpv6={} tx_gso_other={} tx_gso_size_max={}",
            self.sample,
            self.bytes,
            wall_ms,
            self.epoll_wait_calls,
            self.epoll_wait_ns as f64 / 1_000_000.0,
            self.epoll_wait_max_ns as f64 / 1_000_000.0,
            self.epoll_batches,
            self.epoll_events,
            self.queue_events,
            self.queue_event_reads,
            self.queue_event_value_sum,
            self.queue_event_value_max,
            Self::average_us(self.queue_event_gap_ns, self.queue_event_gap_samples),
            self.queue_event_gap_max_ns as f64 / 1_000.0,
            self.queue_event_gap_over_100us,
            self.queue_event_gap_over_250us,
            self.queue_event_gap_over_500us,
            self.queue_event_gap_over_1ms,
            self.timer_events,
            self.backend_writable_events,
            self.tx_loop_calls,
            self.tx_loop_ns as f64 / 1_000_000.0,
            self.process_tx_calls,
            self.process_tx_ns as f64 / 1_000_000.0,
            self.descriptor_chains,
            self.descriptors,
            chains_per_process_tx,
            descriptors_per_chain,
            self.max_chains_per_process_tx,
            self.guest_read_calls,
            self.guest_read_ns as f64 / 1_000_000.0,
            self.backend_write_calls,
            self.backend_write_ns as f64 / 1_000_000.0,
            self.flush_calls,
            self.flush_ns as f64 / 1_000_000.0,
            self.deferred_stalls,
            self.notification_enable_calls,
            self.notification_races,
            self.completion_batches,
            self.add_used_calls,
            self.add_used_ns as f64 / 1_000_000.0,
            self.irq_signals,
            self.irq_suppressed,
            self.irq_signal_ns as f64 / 1_000_000.0,
            self.completion_to_irq_samples,
            Self::average_us(self.completion_to_irq_ns, self.completion_to_irq_samples),
            self.completion_to_irq_max_ns as f64 / 1_000.0,
            self.tx_frame_bytes,
            self.tx_frame_min,
            self.tx_frame_max,
            self.tx_tcp_frames,
            self.tx_tcp_data_frames,
            self.tx_tcp_payload_bytes,
            self.tx_csum_needed,
            self.tx_gso_none,
            self.tx_gso_tcpv4,
            self.tx_gso_tcpv6,
            self.tx_gso_other,
            self.tx_gso_size_max,
        );

        eprintln!(
            "libkrun: virtio-net rx feedback profile sample={} rx_queue_events={} rx_backend_events={} \
process_rx_calls={} process_rx_ms={:.3} backend_read_calls={} backend_read_empty={} backend_read_ms={:.3} guest_write_calls={} \
guest_write_ms={:.3} rx_frames={} rx_bytes={} rx_tcp_frames={} rx_tcp_ack_only={} rx_tcp_payload_frames={} \
rx_tcp_payload_bytes={} rx_irq_signals={} rx_irq_signal_ms={:.3} rx_deferred_frames={} \
ack_interarrival_samples={} ack_interarrival_avg_us={:.3} ack_interarrival_max_us={:.3} \
ack_interarrival_ge_100us={} ack_interarrival_ge_250us={} ack_interarrival_ge_500us={} \
ack_interarrival_ge_1ms={} ack_backend_to_guest_samples={} ack_backend_to_guest_avg_us={:.3} \
ack_backend_to_guest_max_us={:.3} ack_to_irq_samples={} ack_to_irq_avg_us={:.3} ack_to_irq_max_us={:.3} \
ack_to_tx_samples={} ack_to_tx_avg_us={:.3} ack_to_tx_max_us={:.3} ack_to_tx_ge_100us={} \
ack_to_tx_ge_250us={} ack_to_tx_ge_500us={} ack_to_tx_ge_1ms={} last_tx_data_to_ack_samples={} \
last_tx_data_to_ack_avg_us={:.3} last_tx_data_to_ack_max_us={:.3}",
            self.sample,
            self.rx_queue_events,
            self.rx_backend_events,
            self.process_rx_calls,
            self.process_rx_ns as f64 / 1_000_000.0,
            self.backend_read_calls,
            self.backend_read_empty,
            self.backend_read_ns as f64 / 1_000_000.0,
            self.guest_write_calls,
            self.guest_write_ns as f64 / 1_000_000.0,
            self.rx_frames,
            self.rx_bytes,
            self.rx_tcp_frames,
            self.rx_tcp_ack_only,
            self.rx_tcp_payload_frames,
            self.rx_tcp_payload_bytes,
            self.rx_irq_signals,
            self.rx_irq_signal_ns as f64 / 1_000_000.0,
            self.rx_deferred_frames,
            self.ack_interarrival_samples,
            Self::average_us(self.ack_interarrival_ns, self.ack_interarrival_samples),
            self.ack_interarrival_max_ns as f64 / 1_000.0,
            self.ack_interarrival_over_100us,
            self.ack_interarrival_over_250us,
            self.ack_interarrival_over_500us,
            self.ack_interarrival_over_1ms,
            self.ack_backend_to_guest_samples,
            Self::average_us(self.ack_backend_to_guest_ns, self.ack_backend_to_guest_samples),
            self.ack_backend_to_guest_max_ns as f64 / 1_000.0,
            self.ack_to_irq_samples,
            Self::average_us(self.ack_to_irq_ns, self.ack_to_irq_samples),
            self.ack_to_irq_max_ns as f64 / 1_000.0,
            self.ack_to_tx_samples,
            Self::average_us(self.ack_to_tx_ns, self.ack_to_tx_samples),
            self.ack_to_tx_max_ns as f64 / 1_000.0,
            self.ack_to_tx_over_100us,
            self.ack_to_tx_over_250us,
            self.ack_to_tx_over_500us,
            self.ack_to_tx_over_1ms,
            self.last_tx_data_to_ack_samples,
            Self::average_us(self.last_tx_data_to_ack_ns, self.last_tx_data_to_ack_samples),
            self.last_tx_data_to_ack_max_ns as f64 / 1_000.0,
        );

        let next_sample = self.sample + 1;
        let enabled = self.enabled;
        *self = Self::new(enabled);
        self.sample = next_sample;
        true
    }
}

pub struct NetWorker {
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,
    tx_has_deferred_frame: bool,
    tx_profile: TxProfile,
    last_tx_queue_event_at: Option<Instant>,
    last_rx_ack_at: Option<Instant>,
    last_rx_ack_delivered_at: Option<Instant>,
    pending_rx_ack_read_at: Option<Instant>,
    pending_rx_ack_for_irq_at: Option<Instant>,
    last_tx_data_at: Option<Instant>,
}

impl NetWorker {
    pub fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        cfg_backend: VirtioNetBackend,
    ) -> Result<Self, ConnectError> {
        #[cfg(target_os = "macos")]
        let profile_vmnet_tx = matches!(&cfg_backend, VirtioNetBackend::VmnetFd(_));
        #[cfg(not(target_os = "macos"))]
        let profile_vmnet_tx = false;

        let backend = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixstreamPath(path) => {
                Box::new(Unixstream::open(path)?) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "macos")]
            VirtioNetBackend::VmnetFd(fd) => {
                // SAFETY: the native vmnet bridge created and transferred this socketpair fd.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new_batched(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => {
                Box::new(Unixgram::open(path, vfkit_magic)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => {
                Box::new(Tap::new(tap_name, _vnet_features)?) as Box<dyn NetBackend + Send>
            }
        };

        Ok(Self {
            rx_q,
            tx_q,

            mem,
            backend,
            interrupt,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            tx_has_deferred_frame: false,
            tx_profile: TxProfile::new(profile_vmnet_tx),
            last_tx_queue_event_at: None,
            last_rx_ack_at: None,
            last_rx_ack_delivered_at: None,
            pending_rx_ack_read_at: None,
            pending_rx_ack_for_irq_at: None,
            last_tx_data_at: None,
        })
    }

    pub fn run(self) {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap();
    }

    fn work(mut self) {
        #[cfg(target_os = "macos")]
        const TX_TIMER_FD: RawFd = -2;

        let virtq_rx_ev_fd = self.rx_q.event.as_raw_fd();
        let virtq_tx_ev_fd = self.tx_q.event.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_rx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_tx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
                backend_socket as u64,
            ),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            let wait_started = self.tx_profile.enabled.then(Instant::now);
            let wait_result = epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice());
            if let Some(started) = wait_started {
                self.tx_profile.epoll_wait_calls += 1;
                let elapsed = TxProfile::add_elapsed(&mut self.tx_profile.epoll_wait_ns, started);
                self.tx_profile.epoll_wait_max_ns = self.tx_profile.epoll_wait_max_ns.max(elapsed);
            }
            match wait_result {
                Ok(ev_cnt) => {
                    if self.tx_profile.enabled {
                        self.tx_profile.epoll_batches += 1;
                        self.tx_profile.epoll_events += ev_cnt as u64;
                    }
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_rx_ev_fd => {
                                self.process_rx_queue_event();
                            }
                            EventSet::IN if source == virtq_tx_ev_fd => {
                                self.process_tx_queue_event();
                            }
                            _ if source == backend_socket => {
                                if event_set.contains(EventSet::HANG_UP)
                                    || event_set.contains(EventSet::READ_HANG_UP)
                                {
                                    log::error!("Got {event_set:?} on backend fd, virtio-net will stop working");
                                    eprintln!("LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!");
                                } else {
                                    if event_set.contains(EventSet::IN) {
                                        self.process_backend_socket_readable()
                                    }

                                    if event_set.contains(EventSet::OUT) {
                                        self.process_backend_socket_writeable()
                                    }
                                }
                            }
                            #[cfg(target_os = "macos")]
                            _ if event_set.is_empty() && source == TX_TIMER_FD => {
                                if self.tx_profile.enabled {
                                    self.tx_profile.timer_events += 1;
                                }
                                self.process_tx_loop();
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }

                    // Arm the retry timer after processing all events, so it
                    // reflects the final state of tx_has_deferred_frame.
                    #[cfg(target_os = "macos")]
                    if self.tx_has_deferred_frame {
                        let delay = self.backend.write_retry_delay_us();
                        if delay > 0 {
                            epoll.add_oneshot_timer(delay, TX_TIMER_FD as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if self.tx_profile.enabled {
            self.tx_profile.rx_queue_events += 1;
        }
        if let Err(e) = self.rx_q.event.read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by queue event)")
        };
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        let now = self.tx_profile.enabled.then(Instant::now);
        if let Some(now) = now {
            self.tx_profile.queue_events += 1;
            if let Some(previous) = self.last_tx_queue_event_at.replace(now) {
                self.tx_profile.record_queue_event_gap(now.duration_since(previous).as_nanos());
            }
            if let Some(ack) = self.last_rx_ack_delivered_at.take() {
                self.tx_profile.record_ack_to_tx(now.duration_since(ack).as_nanos());
            }
        }
        match self.tx_q.event.read() {
            Ok(value) => {
                if self.tx_profile.enabled {
                    self.tx_profile.queue_event_reads += 1;
                    self.tx_profile.queue_event_value_sum =
                        self.tx_profile.queue_event_value_sum.saturating_add(value);
                    self.tx_profile.queue_event_value_max =
                        self.tx_profile.queue_event_value_max.max(value);
                }
                self.process_tx_loop();
            }
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_backend_socket_readable(&mut self) {
        if self.tx_profile.enabled {
            self.tx_profile.rx_backend_events += 1;
        }
        if let Err(e) = self.rx_q.queue.enable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
        if let Err(e) = self.process_rx() {
            log::error!("Failed to process rx: {e:?} (triggered by backend socket readable)");
        };
        if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
            error!("error disabling queue notifications: {e:?}");
        }
    }

    pub(crate) fn process_backend_socket_writeable(&mut self) {
        if self.tx_profile.enabled {
            self.tx_profile.backend_writable_events += 1;
        }
        let flush_started = self.tx_profile.enabled.then(Instant::now);
        let result = self
            .backend
            .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len]);
        if let Some(started) = flush_started {
            self.tx_profile.flush_calls += 1;
            TxProfile::add_elapsed(&mut self.tx_profile.flush_ns, started);
        }
        match result {
            Ok(()) => self.process_tx_loop(),
            Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
            Err(e @ WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        let profile_started = self.tx_profile.enabled.then(Instant::now);
        if self.tx_profile.enabled {
            self.tx_profile.process_rx_calls += 1;
        }

        // If we have a deferred frame, try it first. If the guest still has no
        // receive buffer available, preserve the frame and wait for another RX kick.
        if self.rx_has_deferred_frame {
            if self.tx_profile.enabled {
                self.tx_profile.rx_deferred_frames += 1;
            }
            if self.write_frame_to_guest() {
                self.rx_has_deferred_frame = false;
            } else {
                if let Some(started) = profile_started {
                    TxProfile::add_elapsed(&mut self.tx_profile.process_rx_ns, started);
                }
                return Ok(());
            }
        }

        let mut signal_queue = false;

        // Read as many frames as possible.
        let result = loop {
            match self.read_into_rx_frame_buf_from_backend() {
                Ok(()) => {
                    if self.write_frame_to_guest() {
                        signal_queue = true;
                    } else {
                        self.rx_has_deferred_frame = true;
                        if self.tx_profile.enabled {
                            self.tx_profile.rx_deferred_frames += 1;
                        }
                        break Ok(());
                    }
                }
                Err(ReadError::NothingRead) => break Ok(()),
                Err(e @ ReadError::Internal(_)) => break Err(RxError::Backend(e)),
            }
        };

        // At this point we processed as many Rx frames as possible.
        // We have to wake the guest if at least one descriptor chain has been used.
        if signal_queue {
            let irq_started = self.tx_profile.enabled.then(Instant::now);
            if self.tx_profile.enabled {
                self.tx_profile.rx_irq_signals += 1;
            }
            if let Err(error) = self.interrupt.try_signal_used_queue() {
                if let Some(started) = irq_started {
                    TxProfile::add_elapsed(&mut self.tx_profile.rx_irq_signal_ns, started);
                }
                if let Some(started) = profile_started {
                    TxProfile::add_elapsed(&mut self.tx_profile.process_rx_ns, started);
                }
                return Err(RxError::DeviceError(error));
            }
            if let Some(started) = irq_started {
                TxProfile::add_elapsed(&mut self.tx_profile.rx_irq_signal_ns, started);
            }
            if self.tx_profile.enabled {
                if let Some(ack_delivered) = self.pending_rx_ack_for_irq_at.take() {
                    self.tx_profile
                        .record_ack_to_irq(ack_delivered.elapsed().as_nanos());
                }
            }
        }

        if let Some(started) = profile_started {
            TxProfile::add_elapsed(&mut self.tx_profile.process_rx_ns, started);
        }
        result
    }

    fn process_tx_loop(&mut self) {
        let loop_started = self.tx_profile.enabled.then(Instant::now);
        if self.tx_profile.enabled {
            self.tx_profile.tx_loop_calls += 1;
        }

        loop {
            self.tx_q.queue.disable_notification(&self.mem).unwrap();

            let process_started = self.tx_profile.enabled.then(Instant::now);
            let chains_before = self.tx_profile.descriptor_chains;
            let result = self.process_tx();
            if let Some(started) = process_started {
                self.tx_profile.process_tx_calls += 1;
                TxProfile::add_elapsed(&mut self.tx_profile.process_tx_ns, started);
                self.tx_profile.max_chains_per_process_tx = self
                    .tx_profile
                    .max_chains_per_process_tx
                    .max(self.tx_profile.descriptor_chains.saturating_sub(chains_before));
            }

            self.tx_has_deferred_frame = match result {
                Err(TxError::Backend(WriteError::NothingWritten)) => {
                    if self.tx_profile.enabled {
                        self.tx_profile.deferred_stalls += 1;
                    }
                    true
                }
                Err(e) => {
                    log::error!("Failed to process tx: {e:?}");
                    false
                }
                _ => false,
            };

            let has_new_entries = self.tx_q.queue.enable_notification(&self.mem).unwrap();
            if self.tx_profile.enabled {
                self.tx_profile.notification_enable_calls += 1;
                if has_new_entries {
                    self.tx_profile.notification_races += 1;
                }
            }
            if self.tx_has_deferred_frame || !has_new_entries {
                break;
            }
        }

        if let Some(started) = loop_started {
            TxProfile::add_elapsed(&mut self.tx_profile.tx_loop_ns, started);
            if self.tx_profile.maybe_print() {
                self.last_tx_queue_event_at = None;
                self.last_rx_ack_at = None;
                self.last_rx_ack_delivered_at = None;
                self.pending_rx_ack_read_at = None;
                self.pending_rx_ack_for_irq_at = None;
                self.last_tx_data_at = None;
            }
        }
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let tx_queue = &mut self.tx_q.queue;

        if self.backend.has_unfinished_write() {
            let flush_started = self.tx_profile.enabled.then(Instant::now);
            let flush_result = self
                .backend
                .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len]);
            if let Some(started) = flush_started {
                self.tx_profile.flush_calls += 1;
                TxProfile::add_elapsed(&mut self.tx_profile.flush_ns, started);
            }
            match flush_result {
                Ok(()) => {}
                Err(WriteError::NothingWritten) => {
                    return Err(TxError::Backend(WriteError::NothingWritten));
                }
                Err(_) => {
                    log::trace!("Cannot process tx because of unfinished partial write!");
                    return Ok(());
                }
            }
        }

        let mut raise_irq = false;
        let mut first_completion_at = None;
        let mut result = Ok(());

        while let Some(head) = tx_queue.pop(&self.mem) {
            if self.tx_profile.enabled {
                self.tx_profile.descriptor_chains += 1;
            }
            let head_index = head.index;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if self.tx_profile.enabled {
                    self.tx_profile.descriptors += 1;
                }
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            let guest_read_started = self.tx_profile.enabled.then(Instant::now);
            let mut read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {e:?}");
                        read_count = 0;
                        break;
                    }
                }
            }

            if let Some(started) = guest_read_started {
                self.tx_profile.guest_read_calls += 1;
                TxProfile::add_elapsed(&mut self.tx_profile.guest_read_ns, started);
            }

            self.tx_frame_len = read_count;
            let backend_write_started = self.tx_profile.enabled.then(Instant::now);
            let write_result = self
                .backend
                .write_frame(VNET_HDR_LEN, &mut self.tx_frame_buf[..read_count]);
            if let Some(started) = backend_write_started {
                self.tx_profile.backend_write_calls += 1;
                TxProfile::add_elapsed(&mut self.tx_profile.backend_write_ns, started);
            }
            match write_result {
                Ok(()) => {
                    if self.tx_profile.enabled {
                        let (summary, started_sample) =
                            self.tx_profile.record_tx_frame(&self.tx_frame_buf[..read_count]);
                        if started_sample {
                            self.last_tx_queue_event_at = None;
                            self.last_rx_ack_at = None;
                            self.last_rx_ack_delivered_at = None;
                            self.pending_rx_ack_read_at = None;
                            self.pending_rx_ack_for_irq_at = None;
                            self.last_tx_data_at = None;
                        }
                        if summary.tcp_payload_bytes > 0 {
                            self.last_tx_data_at = Some(Instant::now());
                        }
                    }
                    self.tx_frame_len = 0;
                    let add_used_started = self.tx_profile.enabled.then(Instant::now);
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    if let Some(started) = add_used_started {
                        self.tx_profile.add_used_calls += 1;
                        TxProfile::add_elapsed(&mut self.tx_profile.add_used_ns, started);
                        first_completion_at.get_or_insert(started);
                    }
                    raise_irq = true;
                }
                Err(WriteError::NothingWritten) => {
                    tx_queue.undo_pop();
                    result = Err(TxError::Backend(WriteError::NothingWritten));
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the backend socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for the backend to process our sending frames, because
                    the backend could be blocked on sending a remainder of a frame to us - us waiting
                    for backend would cause a deadlock.
                     */
                    let add_used_started = self.tx_profile.enabled.then(Instant::now);
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    if let Some(started) = add_used_started {
                        self.tx_profile.add_used_calls += 1;
                        TxProfile::add_elapsed(&mut self.tx_profile.add_used_ns, started);
                        first_completion_at.get_or_insert(started);
                    }
                    raise_irq = true;
                    break;
                }
                Err(e @ WriteError::Internal(_) | e @ WriteError::ProcessNotRunning) => {
                    return Err(TxError::Backend(e))
                }
            }
        }

        if result.is_ok() {
            let flush_started = self.tx_profile.enabled.then(Instant::now);
            let flush_result = self.backend.flush_writes();
            if let Some(started) = flush_started {
                self.tx_profile.flush_calls += 1;
                TxProfile::add_elapsed(&mut self.tx_profile.flush_ns, started);
            }
            if let Err(e) = flush_result {
                result = Err(TxError::Backend(e));
            }
        }

        if raise_irq {
            if self.tx_profile.enabled {
                self.tx_profile.completion_batches += 1;
            }
            if tx_queue.needs_notification(&self.mem).unwrap() {
                let irq_started = self.tx_profile.enabled.then(Instant::now);
                if self.tx_profile.enabled {
                    self.tx_profile.irq_signals += 1;
                }
                self.interrupt
                    .try_signal_used_queue()
                    .map_err(TxError::DeviceError)?;
                if let Some(started) = irq_started {
                    TxProfile::add_elapsed(&mut self.tx_profile.irq_signal_ns, started);
                }
                if let Some(completion) = first_completion_at {
                    let elapsed = completion.elapsed().as_nanos();
                    self.tx_profile.completion_to_irq_samples += 1;
                    self.tx_profile.completion_to_irq_ns += elapsed;
                    self.tx_profile.completion_to_irq_max_ns =
                        self.tx_profile.completion_to_irq_max_ns.max(elapsed);
                }
            } else if self.tx_profile.enabled {
                self.tx_profile.irq_suppressed += 1;
            }
        }

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());

        let queue = &mut self.rx_q.queue;
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {e:?}");
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let started = self.tx_profile.enabled.then(Instant::now);
        if self.tx_profile.enabled {
            self.tx_profile.guest_write_calls += 1;
        }
        let max_iterations = self.rx_q.queue.actual_size();
        let mut delivered = false;
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => {
                    delivered = true;
                    break;
                }
                Err(FrontendError::EmptyQueue) => {
                    // retry
                    continue;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        if let Some(started) = started {
            TxProfile::add_elapsed(&mut self.tx_profile.guest_write_ns, started);
        }
        if delivered && self.tx_profile.enabled {
            let summary = self
                .tx_profile
                .record_rx_delivery(&self.rx_frame_buf[..self.rx_frame_buf_len]);
            if summary.tcp_ack_only {
                let now = Instant::now();
                if let Some(read_at) = self.pending_rx_ack_read_at.take() {
                    self.tx_profile
                        .record_ack_backend_to_guest(now.duration_since(read_at).as_nanos());
                }
                self.last_rx_ack_delivered_at = Some(now);
                if self.pending_rx_ack_for_irq_at.is_none() {
                    self.pending_rx_ack_for_irq_at = Some(now);
                }
            } else {
                self.pending_rx_ack_read_at = None;
            }
        }
        delivered
    }

    /// Fills self.rx_frame_buf with an ethernet frame from backend and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_backend(&mut self) -> result::Result<(), ReadError> {
        let started = self.tx_profile.enabled.then(Instant::now);
        if self.tx_profile.enabled {
            self.tx_profile.backend_read_calls += 1;
        }
        let result = self.backend.read_frame(&mut self.rx_frame_buf);
        if let Some(started) = started {
            TxProfile::add_elapsed(&mut self.tx_profile.backend_read_ns, started);
        }
        match result {
            Ok(length) => {
                self.rx_frame_buf_len = length;
                if self.tx_profile.enabled {
                    let summary = summarize_packet(
                        self.rx_frame_buf
                            .get(VNET_HDR_LEN..length)
                            .unwrap_or(&[]),
                    );
                    if summary.tcp_ack_only {
                        let now = Instant::now();
                        if let Some(previous) = self.last_rx_ack_at.replace(now) {
                            self.tx_profile
                                .record_ack_interarrival(now.duration_since(previous).as_nanos());
                        }
                        if let Some(last_tx) = self.last_tx_data_at {
                            let elapsed = now.duration_since(last_tx).as_nanos();
                            self.tx_profile.last_tx_data_to_ack_samples += 1;
                            self.tx_profile.last_tx_data_to_ack_ns += elapsed;
                            self.tx_profile.last_tx_data_to_ack_max_ns =
                                self.tx_profile.last_tx_data_to_ack_max_ns.max(elapsed);
                        }
                        self.pending_rx_ack_read_at = Some(now);
                    } else {
                        self.pending_rx_ack_read_at = None;
                    }
                }
                Ok(())
            }
            Err(ReadError::NothingRead) => {
                if self.tx_profile.enabled {
                    self.tx_profile.backend_read_empty += 1;
                }
                Err(ReadError::NothingRead)
            }
            Err(error) => Err(error),
        }
    }
}
