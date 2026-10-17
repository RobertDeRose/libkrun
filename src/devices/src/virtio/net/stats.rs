use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::virtio::{QueueNotificationCounter, QueueNotificationTimingSnapshot};

#[derive(Clone, Copy, Debug, Default)]
pub struct NetTxStatsSnapshot {
    pub eventfd_wakeups: u64,
    pub eventfd_values: u64,
    pub drain_passes: u64,
    pub empty_drain_passes: u64,
    pub frames: u64,
    pub bytes: u64,
    pub descriptor_chains: u64,
    pub descriptors: u64,
    pub max_frames_per_drain: u64,
    pub max_bytes_per_drain: u64,
    pub write_frame_calls: u64,
    pub backend_bytes: u64,
    pub nothing_written: u64,
    pub partial_writes: u64,
    pub flush_calls: u64,
    pub frames_between_flushes: u64,
    pub bytes_between_flushes: u64,
    pub max_frames_between_flush: u64,
    pub max_bytes_between_flush: u64,
    pub notification_checks: u64,
    pub notification_true: u64,
    pub notification_false: u64,
    pub signal_used_queue_calls: u64,
    pub timing_sampled_frames: u64,
    pub descriptor_parse_sample_ns: u64,
    pub guest_copy_sample_ns: u64,
    pub backend_write_sample_ns: u64,
    pub timing_sampled_flushes: u64,
    pub flush_sample_ns: u64,
    pub timing_sampled_drain_cycles: u64,
    pub timing_sampled_drain_frames: u64,
    pub drain_cycle_sample_ns: u64,
    pub tx_queue_disable_sample_ns: u64,
    pub tx_queue_enable_sample_ns: u64,
    pub add_used_sample_ns: u64,
    pub timing_sampled_notification_checks: u64,
    pub notification_check_sample_ns: u64,
    pub timing_sampled_irq_signals: u64,
    pub irq_signal_sample_ns: u64,
}

impl NetTxStatsSnapshot {
    /// Fold another worker's counters into this one: sums, except the max_*
    /// fields which keep the larger observation.
    pub fn merge(&mut self, other: &NetTxStatsSnapshot) {
        self.eventfd_wakeups += other.eventfd_wakeups;
        self.eventfd_values += other.eventfd_values;
        self.drain_passes += other.drain_passes;
        self.empty_drain_passes += other.empty_drain_passes;
        self.frames += other.frames;
        self.bytes += other.bytes;
        self.descriptor_chains += other.descriptor_chains;
        self.descriptors += other.descriptors;
        self.max_frames_per_drain = self.max_frames_per_drain.max(other.max_frames_per_drain);
        self.max_bytes_per_drain = self.max_bytes_per_drain.max(other.max_bytes_per_drain);
        self.write_frame_calls += other.write_frame_calls;
        self.backend_bytes += other.backend_bytes;
        self.nothing_written += other.nothing_written;
        self.partial_writes += other.partial_writes;
        self.flush_calls += other.flush_calls;
        self.frames_between_flushes += other.frames_between_flushes;
        self.bytes_between_flushes += other.bytes_between_flushes;
        self.max_frames_between_flush = self.max_frames_between_flush.max(other.max_frames_between_flush);
        self.max_bytes_between_flush = self.max_bytes_between_flush.max(other.max_bytes_between_flush);
        self.notification_checks += other.notification_checks;
        self.notification_true += other.notification_true;
        self.notification_false += other.notification_false;
        self.signal_used_queue_calls += other.signal_used_queue_calls;
        self.timing_sampled_frames += other.timing_sampled_frames;
        self.descriptor_parse_sample_ns += other.descriptor_parse_sample_ns;
        self.guest_copy_sample_ns += other.guest_copy_sample_ns;
        self.backend_write_sample_ns += other.backend_write_sample_ns;
        self.timing_sampled_flushes += other.timing_sampled_flushes;
        self.flush_sample_ns += other.flush_sample_ns;
        self.timing_sampled_drain_cycles += other.timing_sampled_drain_cycles;
        self.timing_sampled_drain_frames += other.timing_sampled_drain_frames;
        self.drain_cycle_sample_ns += other.drain_cycle_sample_ns;
        self.tx_queue_disable_sample_ns += other.tx_queue_disable_sample_ns;
        self.tx_queue_enable_sample_ns += other.tx_queue_enable_sample_ns;
        self.add_used_sample_ns += other.add_used_sample_ns;
        self.timing_sampled_notification_checks += other.timing_sampled_notification_checks;
        self.notification_check_sample_ns += other.notification_check_sample_ns;
        self.timing_sampled_irq_signals += other.timing_sampled_irq_signals;
        self.irq_signal_sample_ns += other.irq_signal_sample_ns;
    }
}

struct NetTxStatsShared {
    enabled: AtomicBool,
    reset_epoch: AtomicU64,
    queue_notifications: Arc<QueueNotificationCounter>,
    /// One published snapshot per TX worker, indexed by queue pair.
    snapshots: Mutex<Vec<NetTxStatsSnapshot>>,
}

#[derive(Clone)]
pub struct NetTxStatsHandle(Arc<NetTxStatsShared>);

impl Default for NetTxStatsHandle {
    fn default() -> Self {
        Self(Arc::new(NetTxStatsShared {
            enabled: AtomicBool::new(false),
            reset_epoch: AtomicU64::new(0),
            queue_notifications: Arc::new(QueueNotificationCounter::default()),
            snapshots: Mutex::new(Vec::new()),
        }))
    }
}

impl NetTxStatsHandle {
    pub fn queue_notification_counter(&self) -> Arc<QueueNotificationCounter> {
        self.0.queue_notifications.clone()
    }

    pub fn is_enabled(&self) -> bool {
        self.0.enabled.load(Ordering::Acquire)
    }

    pub fn reset_epoch(&self) -> u64 {
        self.0.reset_epoch.load(Ordering::Acquire)
    }

    pub fn reset_and_enable(&self) {
        self.0.enabled.store(false, Ordering::Release);
        self.0.queue_notifications.set_enabled(false);
        self.0.queue_notifications.reset();
        self.0.snapshots.lock().unwrap().clear();
        self.0.reset_epoch.fetch_add(1, Ordering::AcqRel);
        self.0.queue_notifications.set_enabled(true);
        self.0.enabled.store(true, Ordering::Release);
    }

    pub fn set_worker_waiting(&self, waiting: bool) {
        if self.is_enabled() {
            self.0.queue_notifications.set_worker_waiting(waiting);
        }
    }

    pub fn observe_kqueue_ready(&self, eventfd_sequence: u64) {
        self.0
            .queue_notifications
            .observe_kqueue_ready(eventfd_sequence);
    }

    pub fn observe_eventfd(&self, eventfd_sequence: u64, value: u64) {
        self.0
            .queue_notifications
            .observe_eventfd(eventfd_sequence, value);
    }

    pub fn record_irq_signal(&self, signal_sequence: u64) {
        self.0.queue_notifications.record_irq_signal(signal_sequence);
    }

    pub fn publish(&self, reset_epoch: u64, snapshot: NetTxStatsSnapshot) {
        self.publish_slot(0, reset_epoch, snapshot);
    }

    pub fn publish_slot(&self, slot: usize, reset_epoch: u64, snapshot: NetTxStatsSnapshot) {
        if self.is_enabled() && self.reset_epoch() == reset_epoch {
            let mut snapshots = self.0.snapshots.lock().unwrap();
            if snapshots.len() <= slot {
                snapshots.resize(slot + 1, NetTxStatsSnapshot::default());
            }
            snapshots[slot] = snapshot;
        }
    }

    fn merged(&self) -> NetTxStatsSnapshot {
        let mut merged = NetTxStatsSnapshot::default();
        for snapshot in self.0.snapshots.lock().unwrap().iter() {
            merged.merge(snapshot);
        }
        merged
    }

    pub fn snapshot_and_disable(
        &self,
    ) -> (u64, QueueNotificationTimingSnapshot, NetTxStatsSnapshot) {
        self.0.queue_notifications.set_enabled(false);
        self.0.enabled.store(false, Ordering::Release);
        let queue_notifications = self.0.queue_notifications.load();
        let queue_notification_timing = self.0.queue_notifications.timing_snapshot();
        let snapshot = self.merged();
        (queue_notifications, queue_notification_timing, snapshot)
    }

    #[cfg(test)]
    fn snapshot(&self) -> (u64, NetTxStatsSnapshot) {
        let queue_notifications = self.0.queue_notifications.load();
        let snapshot = self.merged();
        (queue_notifications, snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_notifications_are_counted_only_while_enabled() {
        let handle = NetTxStatsHandle::default();
        let counter = handle.queue_notification_counter();
        let _ = counter.increment();
        assert_eq!(counter.load(), 0);

        handle.reset_and_enable();
        let _ = counter.increment();
        let _ = counter.increment();
        assert_eq!(counter.load(), 2);
    }

    #[test]
    fn snapshot_disables_collection() {
        let handle = NetTxStatsHandle::default();
        handle.reset_and_enable();
        let epoch = handle.reset_epoch();
        handle.publish(
            epoch,
            NetTxStatsSnapshot {
                frames: 3,
                ..Default::default()
            },
        );
        let (_, _, snapshot) = handle.snapshot_and_disable();
        assert_eq!(snapshot.frames, 3);
        assert!(!handle.is_enabled());

        let _ = handle.queue_notification_counter().increment();
        assert_eq!(handle.snapshot().0, 0);
    }

    #[test]
    fn notification_timing_pairs_sampled_notify_with_eventfd_wakeup() {
        let handle = NetTxStatsHandle::default();
        let counter = handle.queue_notification_counter();
        handle.reset_and_enable();
        counter.set_worker_waiting(true);
        for _ in 0..63 {
            let _ = counter.increment();
        }
        let sequence = counter.increment().unwrap();
        counter.record_eventfd_write(sequence, 250);
        handle.observe_kqueue_ready(64);
        handle.observe_eventfd(64, 1);

        let (_, timing, _) = handle.snapshot_and_disable();
        assert_eq!(timing.notify_while_worker_waiting_samples, 1);
        assert_eq!(timing.notify_while_worker_busy_samples, 0);
        assert_eq!(timing.notify_to_kqueue_ready_samples, 1);
        assert_eq!(timing.kqueue_ready_to_eventfd_samples, 1);
        assert_eq!(timing.notify_to_eventfd_samples, 1);
        assert_eq!(timing.eventfd_write_samples, 1);
        assert_eq!(timing.eventfd_write_sample_ns, 250);
        assert_eq!(timing.eventfd_write_max_ns, 250);
    }

    #[test]
    fn notification_timing_pairs_sampled_irq_with_next_notify() {
        let handle = NetTxStatsHandle::default();
        let counter = handle.queue_notification_counter();
        handle.reset_and_enable();
        handle.record_irq_signal(64);
        let _ = counter.increment();

        let (_, timing, _) = handle.snapshot_and_disable();
        assert_eq!(timing.irq_to_next_notify_samples, 1);
    }

    #[test]
    fn reset_discards_published_worker_stats() {
        let handle = NetTxStatsHandle::default();
        handle.reset_and_enable();
        let epoch = handle.reset_epoch();
        handle.publish(
            epoch,
            NetTxStatsSnapshot {
                frames: 7,
                bytes: 4096,
                ..Default::default()
            },
        );
        assert_eq!(handle.snapshot().1.frames, 7);

        handle.reset_and_enable();
        assert_eq!(handle.snapshot().1.frames, 0);
        assert_eq!(handle.snapshot().1.bytes, 0);

        handle.publish(
            epoch,
            NetTxStatsSnapshot {
                frames: 99,
                ..Default::default()
            },
        );
        assert_eq!(handle.snapshot().1.frames, 0);
    }
}
