use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::virtio::QueueNotificationCounter;

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
}

struct NetTxStatsShared {
    enabled: AtomicBool,
    reset_epoch: AtomicU64,
    queue_notifications: Arc<QueueNotificationCounter>,
    snapshot: Mutex<NetTxStatsSnapshot>,
}

#[derive(Clone)]
pub struct NetTxStatsHandle(Arc<NetTxStatsShared>);

impl Default for NetTxStatsHandle {
    fn default() -> Self {
        Self(Arc::new(NetTxStatsShared {
            enabled: AtomicBool::new(false),
            reset_epoch: AtomicU64::new(0),
            queue_notifications: Arc::new(QueueNotificationCounter::default()),
            snapshot: Mutex::new(NetTxStatsSnapshot::default()),
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
        *self.0.snapshot.lock().unwrap() = NetTxStatsSnapshot::default();
        self.0.reset_epoch.fetch_add(1, Ordering::AcqRel);
        self.0.queue_notifications.set_enabled(true);
        self.0.enabled.store(true, Ordering::Release);
    }

    pub fn publish(&self, reset_epoch: u64, snapshot: NetTxStatsSnapshot) {
        if self.is_enabled() && self.reset_epoch() == reset_epoch {
            *self.0.snapshot.lock().unwrap() = snapshot;
        }
    }

    pub fn snapshot_and_disable(&self) -> (u64, NetTxStatsSnapshot) {
        self.0.queue_notifications.set_enabled(false);
        self.0.enabled.store(false, Ordering::Release);
        let queue_notifications = self.0.queue_notifications.load();
        let snapshot = *self.0.snapshot.lock().unwrap();
        (queue_notifications, snapshot)
    }

    #[cfg(test)]
    fn snapshot(&self) -> (u64, NetTxStatsSnapshot) {
        let queue_notifications = self.0.queue_notifications.load();
        let snapshot = *self.0.snapshot.lock().unwrap();
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
        counter.increment();
        assert_eq!(counter.load(), 0);

        handle.reset_and_enable();
        counter.increment();
        counter.increment();
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
        let (_, snapshot) = handle.snapshot_and_disable();
        assert_eq!(snapshot.frames, 3);
        assert!(!handle.is_enabled());

        handle.queue_notification_counter().increment();
        assert_eq!(handle.snapshot().0, 0);
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
