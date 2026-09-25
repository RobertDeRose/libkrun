// SPDX-License-Identifier: Apache-2.0

#include <Availability.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <vmnet/vmnet.h>
#include <xpc/xpc.h>

#define KRUN_VMNET_MAX_FRAME_SIZE 65550
#define KRUN_VMNET_SOCKET_RCVBUF (7 * 1024 * 1024)
#define KRUN_VMNET_MAX_BATCH_PACKETS 64
#define KRUN_VMNET_SOCKET_BATCH_MAGIC "KRUNVMN1"
#define KRUN_VMNET_SOCKET_BATCH_MAGIC_SIZE 8
#define KRUN_VMNET_SOCKET_BATCH_MAX_FRAMES 32
#define KRUN_VMNET_SOCKET_BATCH_HEADER_SIZE 12
#define KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE 4
#define KRUN_VMNET_SOCKET_BATCH_MAX_DATAGRAM (60 * 1024)
#ifndef KRUN_VMNET_TIMEOUT_MS
#define KRUN_VMNET_TIMEOUT_MS 5000
#endif

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000

// Completion blocks may outlive a timed-out caller. Never capture stack storage
// or release the semaphore until both the caller and the block have finished.
struct completion {
    atomic_uint references;
    dispatch_semaphore_t done;
    vmnet_return_t status;
    uint64_t max_packet_size;
    uint64_t read_max_packets;
    uint64_t write_max_packets;
};

struct krun_vmnet_bridge {
    interface_ref interface;
    vmnet_network_ref network;
    xpc_object_t descriptor;
    dispatch_queue_t queue;
    dispatch_semaphore_t tx_done;
    int fd;
    pthread_t tx_thread;
    bool tx_started;
    size_t max_packet_size;
    size_t read_batch_size;
    size_t write_batch_size;
    uint8_t *rx_buffers;
    struct iovec *rx_iovs;
    struct vmpktdesc *rx_packets;
    uint8_t *tx_buffers;
    struct iovec *tx_iovs;
    struct vmpktdesc *tx_packets;
    uint8_t *socket_rx_buffer;
    atomic_bool stopping;
};

static struct completion *completion_create(void)
{
    struct completion *completion = calloc(1, sizeof(*completion));
    if (completion == NULL) {
        return NULL;
    }
    atomic_init(&completion->references, 2); // caller and completion block
    completion->done = dispatch_semaphore_create(0);
    completion->status = VMNET_FAILURE;
    if (completion->done == NULL) {
        free(completion);
        return NULL;
    }
    return completion;
}

static void completion_release(struct completion *completion)
{
    if (atomic_fetch_sub_explicit(&completion->references, 1, memory_order_acq_rel) == 1) {
        dispatch_release(completion->done);
        free(completion);
    }
}

static bool wait_for(dispatch_semaphore_t done)
{
    return dispatch_semaphore_wait(
        done, dispatch_time(DISPATCH_TIME_NOW, KRUN_VMNET_TIMEOUT_MS * NSEC_PER_MSEC)) == 0;
}

static const char *vmnet_status_name(vmnet_return_t status)
{
    switch (status) {
    case VMNET_SUCCESS:
        return "VMNET_SUCCESS";
    case VMNET_FAILURE:
        return "VMNET_FAILURE";
    case VMNET_MEM_FAILURE:
        return "VMNET_MEM_FAILURE";
    case VMNET_INVALID_ARGUMENT:
        return "VMNET_INVALID_ARGUMENT";
    case VMNET_SETUP_INCOMPLETE:
        return "VMNET_SETUP_INCOMPLETE";
    case VMNET_INVALID_ACCESS:
        return "VMNET_INVALID_ACCESS";
    case VMNET_PACKET_TOO_BIG:
        return "VMNET_PACKET_TOO_BIG";
    case VMNET_BUFFER_EXHAUSTED:
        return "VMNET_BUFFER_EXHAUSTED";
    case VMNET_TOO_MANY_PACKETS:
        return "VMNET_TOO_MANY_PACKETS";
    case VMNET_NOT_AUTHORIZED:
        return "VMNET_NOT_AUTHORIZED";
    case VMNET_SHARING_SERVICE_BUSY:
        return "VMNET_SHARING_SERVICE_BUSY";
    default:
        return "VMNET_UNKNOWN";
    }
}

static int vmnet_status_to_errno(vmnet_return_t status)
{
    switch (status) {
    case VMNET_SUCCESS:
        return 0;
    case VMNET_INVALID_ARGUMENT:
        return EINVAL;
    case VMNET_INVALID_ACCESS:
        return EACCES;
    case VMNET_NOT_AUTHORIZED:
        return EPERM;
    case VMNET_MEM_FAILURE:
        return ENOMEM;
    case VMNET_PACKET_TOO_BIG:
        return EMSGSIZE;
    case VMNET_BUFFER_EXHAUSTED:
        return ENOBUFS;
    case VMNET_TOO_MANY_PACKETS:
        return E2BIG;
    case VMNET_SETUP_INCOMPLETE:
        return EAGAIN;
    case VMNET_SHARING_SERVICE_BUSY:
        return EBUSY;
    default:
        return EIO;
    }
}

static int32_t vmnet_framework_error(const char *operation, vmnet_return_t status)
{
    int error = vmnet_status_to_errno(status);
    if (error == 0) {
        // A NULL handle paired with VMNET_SUCCESS is still an API failure.
        error = EIO;
    }
    fprintf(
        stderr,
        "libkrun: vmnet %s failed: status=%u (%s), errno=%d\n",
        operation,
        (unsigned)status,
        vmnet_status_name(status),
        error);
    return -error;
}

static int set_socket_options(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    int fd_flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fd_flags < 0
        || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0
        || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
        return -errno;
    }
#ifdef SO_NOSIGPIPE
    const int no_sigpipe = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) < 0) {
        return -errno;
    }
#endif
    const int rcvbuf = KRUN_VMNET_SOCKET_RCVBUF;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    const int sndbuf = KRUN_VMNET_MAX_FRAME_SIZE;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    return 0;
}

static void reset_packet_batch(
    struct krun_vmnet_bridge *bridge,
    struct iovec *iovs,
    struct vmpktdesc *packets,
    uint8_t *buffers,
    size_t count)
{
    for (size_t i = 0; i < count; i++) {
        iovs[i].iov_base = buffers + i * bridge->max_packet_size;
        iovs[i].iov_len = bridge->max_packet_size;
        packets[i].vm_pkt_size = bridge->max_packet_size;
        packets[i].vm_pkt_iov = &iovs[i];
        packets[i].vm_pkt_iovcnt = 1;
        packets[i].vm_flags = 0;
    }
}

static uint16_t load_u16_be(const uint8_t *data)
{
    uint16_t value;
    memcpy(&value, data, sizeof(value));
    return ntohs(value);
}

static uint32_t load_u32_be(const uint8_t *data)
{
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    return ntohl(value);
}

static void store_u16_be(uint8_t *data, uint16_t value)
{
    value = htons(value);
    memcpy(data, &value, sizeof(value));
}

static void __attribute__((unused)) store_u32_be(uint8_t *data, uint32_t value)
{
    value = htonl(value);
    memcpy(data, &value, sizeof(value));
}

static bool send_guest_packet_group(
    struct krun_vmnet_bridge *bridge,
    struct vmpktdesc *packets,
    size_t count)
{
    if (count == 0) {
        return true;
    }
    if (count == 1
        && packets[0].vm_pkt_size + KRUN_VMNET_SOCKET_BATCH_HEADER_SIZE
               + KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE
            > KRUN_VMNET_SOCKET_BATCH_MAX_DATAGRAM) {
        ssize_t written = send(
            bridge->fd, packets[0].vm_pkt_iov->iov_base, packets[0].vm_pkt_size, 0);
        return written == (ssize_t)packets[0].vm_pkt_size
            || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS;
    }

    uint8_t header[KRUN_VMNET_SOCKET_BATCH_HEADER_SIZE] = {0};
    uint32_t lengths[KRUN_VMNET_SOCKET_BATCH_MAX_FRAMES];
    memcpy(header, KRUN_VMNET_SOCKET_BATCH_MAGIC, KRUN_VMNET_SOCKET_BATCH_MAGIC_SIZE);
    store_u16_be(header + 8, (uint16_t)count);

    struct iovec iovs[1 + KRUN_VMNET_SOCKET_BATCH_MAX_FRAMES * 2];
    iovs[0].iov_base = header;
    iovs[0].iov_len = sizeof(header);
    size_t total = sizeof(header);
    for (size_t i = 0; i < count; i++) {
        lengths[i] = htonl((uint32_t)packets[i].vm_pkt_size);
        iovs[1 + i * 2].iov_base = &lengths[i];
        iovs[1 + i * 2].iov_len = sizeof(lengths[i]);
        iovs[2 + i * 2] = *packets[i].vm_pkt_iov;
        iovs[2 + i * 2].iov_len = packets[i].vm_pkt_size;
        total += sizeof(lengths[i]) + packets[i].vm_pkt_size;
    }
    struct msghdr message = {
        .msg_iov = iovs,
        .msg_iovlen = (int)(1 + count * 2),
    };
    ssize_t written = sendmsg(bridge->fd, &message, 0);
    return written == (ssize_t)total
        || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS;
}

static void send_guest_packet_batch(
    struct krun_vmnet_bridge *bridge,
    struct vmpktdesc *packets,
    size_t count)
{
    size_t offset = 0;
    while (offset < count) {
        size_t group_count = 0;
        size_t group_size = KRUN_VMNET_SOCKET_BATCH_HEADER_SIZE;
        while (offset + group_count < count
               && group_count < KRUN_VMNET_SOCKET_BATCH_MAX_FRAMES) {
            size_t packet_size = packets[offset + group_count].vm_pkt_size;
            if (packet_size > bridge->max_packet_size) {
                return;
            }
            if (group_count > 0
                && group_size + KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE + packet_size
                    > KRUN_VMNET_SOCKET_BATCH_MAX_DATAGRAM) {
                break;
            }
            if (group_count == 0
                && packet_size + KRUN_VMNET_SOCKET_BATCH_HEADER_SIZE
                       + KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE
                    > KRUN_VMNET_SOCKET_BATCH_MAX_DATAGRAM) {
                if (!send_guest_packet_group(bridge, &packets[offset], 1)) {
                    return;
                }
                offset++;
                group_count = 0;
                break;
            }
            group_size += KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE + packet_size;
            group_count++;
        }
        if (group_count == 0) {
            continue;
        }
        if (!send_guest_packet_group(bridge, &packets[offset], group_count)) {
            return;
        }
        offset += group_count;
    }
}

static int decode_socket_batch(
    struct krun_vmnet_bridge *bridge,
    const uint8_t *data,
    size_t length,
    size_t base,
    size_t capacity,
    size_t *out_count)
{
    *out_count = 0;
    if (length > KRUN_VMNET_SOCKET_BATCH_MAX_DATAGRAM
        || length < KRUN_VMNET_SOCKET_BATCH_HEADER_SIZE
               + KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE
        || memcmp(data, KRUN_VMNET_SOCKET_BATCH_MAGIC,
                  KRUN_VMNET_SOCKET_BATCH_MAGIC_SIZE) != 0) {
        return 0;
    }
    size_t count = load_u16_be(data + 8);
    if (count == 0 || count > KRUN_VMNET_SOCKET_BATCH_MAX_FRAMES
        || count > capacity - base
        || data[10] != 0 || data[11] != 0) {
        return -1;
    }
    size_t offset = KRUN_VMNET_SOCKET_BATCH_HEADER_SIZE;
    for (size_t i = 0; i < count; i++) {
        if (offset + KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE > length) {
            return -1;
        }
        size_t frame_length = load_u32_be(data + offset);
        offset += KRUN_VMNET_SOCKET_BATCH_FRAME_HEADER_SIZE;
        if (frame_length == 0 || frame_length > bridge->max_packet_size
            || offset + frame_length > length) {
            return -1;
        }
        size_t slot = base + i;
        memcpy(
            bridge->tx_buffers + slot * bridge->max_packet_size,
            data + offset,
            frame_length);
        bridge->tx_iovs[slot].iov_base = bridge->tx_buffers + slot * bridge->max_packet_size;
        bridge->tx_iovs[slot].iov_len = frame_length;
        bridge->tx_packets[slot].vm_pkt_size = frame_length;
        bridge->tx_packets[slot].vm_pkt_iov = &bridge->tx_iovs[slot];
        bridge->tx_packets[slot].vm_pkt_iovcnt = 1;
        bridge->tx_packets[slot].vm_flags = 0;
        offset += frame_length;
    }
    if (offset != length) {
        return -1;
    }
    *out_count = count;
    return 1;
}

static void forward_packets_to_guest(struct krun_vmnet_bridge *bridge, xpc_object_t event)
{
    if (atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        return;
    }
    uint64_t available = xpc_dictionary_get_uint64(event, vmnet_estimated_packets_available_key);
    // Check stopping between batches rather than capping the advertised total:
    // leaving queued frames unread can lose an edge-triggered notification.
    available = available == 0 ? 1 : available;
    while (available > 0 && !atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        size_t requested = available < bridge->read_batch_size
            ? (size_t)available
            : bridge->read_batch_size;
        reset_packet_batch(
            bridge, bridge->rx_iovs, bridge->rx_packets, bridge->rx_buffers, requested);
        int count = (int)requested;
        vmnet_return_t status = vmnet_read(bridge->interface, bridge->rx_packets, &count);
        if (status != VMNET_SUCCESS || count <= 0 || (size_t)count > requested) {
            break;
        }
        send_guest_packet_batch(bridge, bridge->rx_packets, (size_t)count);
        available -= (uint64_t)count;
    }
}

static size_t receive_packet_batch(struct krun_vmnet_bridge *bridge)
{
    size_t count = 0;
    while (count < KRUN_VMNET_SOCKET_BATCH_MAX_FRAMES
           && !atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        // Native TSO makes raw datagrams large enough that the extra copy from
        // socket_rx_buffer into the vmnet TX slot is measurable. Receive
        // directly into that slot when it is also large enough for a possible
        // private batch datagram. Batched datagrams still use the scratch
        // buffer for decoding so the wire format and decoder stay unchanged.
        bool direct = bridge->max_packet_size >= KRUN_VMNET_SOCKET_BATCH_MAX_DATAGRAM;
        uint8_t *packet_buffer = bridge->tx_buffers + count * bridge->max_packet_size;
        uint8_t *receive_buffer = direct ? packet_buffer : bridge->socket_rx_buffer;
        size_t receive_capacity = direct ? bridge->max_packet_size : KRUN_VMNET_MAX_FRAME_SIZE;
        struct iovec iov = {
            .iov_base = receive_buffer,
            .iov_len = receive_capacity,
        };
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
        ssize_t length = recvmsg(bridge->fd, &message, 0);
        if (length < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                atomic_store_explicit(&bridge->stopping, true, memory_order_relaxed);
            }
            break;
        }
        if (length == 0 || (message.msg_flags & MSG_TRUNC) != 0) {
            continue;
        }

        const uint8_t *data = receive_buffer;
        if (direct && (size_t)length <= KRUN_VMNET_SOCKET_BATCH_MAX_DATAGRAM
            && (size_t)length >= KRUN_VMNET_SOCKET_BATCH_MAGIC_SIZE
            && memcmp(receive_buffer, KRUN_VMNET_SOCKET_BATCH_MAGIC,
                      KRUN_VMNET_SOCKET_BATCH_MAGIC_SIZE) == 0) {
            memcpy(bridge->socket_rx_buffer, receive_buffer, (size_t)length);
            data = bridge->socket_rx_buffer;
        }

        size_t decoded = 0;
        int batch = decode_socket_batch(
            bridge, data, (size_t)length, count,
            KRUN_VMNET_MAX_BATCH_PACKETS, &decoded);
        if (batch < 0) {
            continue;
        }
        if (batch > 0) {
            count += decoded;
            return count;
        }
        if ((size_t)length > bridge->max_packet_size) {
            continue;
        }
        reset_packet_batch(
            bridge, &bridge->tx_iovs[count], &bridge->tx_packets[count],
            packet_buffer, 1);
        if (!direct) {
            memcpy(packet_buffer, bridge->socket_rx_buffer, (size_t)length);
        }
        bridge->tx_iovs[count].iov_len = (size_t)length;
        bridge->tx_packets[count].vm_pkt_size = (size_t)length;
        count++;
    }
    return count;
}

static void write_packet_batch(struct krun_vmnet_bridge *bridge, size_t received)
{
    size_t offset = 0;
    while (offset < received && !atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        size_t requested = received - offset;
        if (requested > bridge->write_batch_size) {
            requested = bridge->write_batch_size;
        }
        int count = (int)requested;
        vmnet_return_t status = vmnet_write(bridge->interface, &bridge->tx_packets[offset], &count);
        if (status != VMNET_SUCCESS || count <= 0 || (size_t)count > requested) {
            break;
        }
        offset += (size_t)count;
    }
}

static void *forward_packets_to_vmnet(void *opaque)
{
    struct krun_vmnet_bridge *bridge = opaque;
    while (!atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        struct pollfd pollfd = {.fd = bridge->fd, .events = POLLIN};
        int ready = poll(&pollfd, 1, 100);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready == 0) {
            continue;
        }
        if ((pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            break;
        }
        while (!atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
            size_t received = receive_packet_batch(bridge);
            if (received == 0) {
                break;
            }
            write_packet_batch(bridge, received);
        }
    }
    dispatch_semaphore_signal(bridge->tx_done);
    return NULL;
}

static void destroy_bridge(struct krun_vmnet_bridge *bridge)
{
    if (bridge->fd >= 0) {
        close(bridge->fd);
    }
    if (bridge->queue != NULL) {
        dispatch_release(bridge->queue);
    }
    if (bridge->tx_done != NULL) {
        dispatch_release(bridge->tx_done);
    }
    if (bridge->descriptor != NULL) {
        xpc_release(bridge->descriptor);
    }
    if (bridge->network != NULL) {
        CFRelease(bridge->network);
    }
    free(bridge->rx_packets);
    free(bridge->rx_iovs);
    free(bridge->rx_buffers);
    free(bridge->tx_packets);
    free(bridge->tx_iovs);
    free(bridge->tx_buffers);
    free(bridge->socket_rx_buffer);
    free(bridge);
}

static void quarantine(const char *operation)
{
    // A missing framework acknowledgement leaves callback/thread ownership
    // uncertain. Do not free a live bridge. The per-VM owner must exit on a
    // startup failure; process teardown reclaims these exceptional resources.
    fprintf(stderr, "libkrun: vmnet %s; native resources retained until process exit\n", operation);
}

static bool stop_bridge(struct krun_vmnet_bridge *bridge)
{
    atomic_store_explicit(&bridge->stopping, true, memory_order_relaxed);
    if (bridge->tx_started) {
        if (!wait_for(bridge->tx_done)) {
            quarantine("TX shutdown timed out");
            return false;
        }
        (void)pthread_join(bridge->tx_thread, NULL);
        bridge->tx_started = false;
    }
    if (bridge->interface != NULL) {
        struct completion *completion = completion_create();
        if (completion == NULL) {
            quarantine("stop completion allocation failed");
            return false;
        }
        vmnet_return_t submitted = vmnet_stop_interface(
            bridge->interface, bridge->queue, ^(vmnet_return_t status) {
                completion->status = status;
                dispatch_semaphore_signal(completion->done);
                completion_release(completion);
            });
        bool stopped = submitted == VMNET_SUCCESS && wait_for(completion->done);
        bool success = stopped && completion->status == VMNET_SUCCESS;
        // If submission failed, no completion is promised. Keep its block ref
        // too: a late callback must remain safe even on this failure path.
        completion_release(completion);
        if (!success) {
            quarantine("interface stop failed or timed out");
            return false;
        }
        bridge->interface = NULL;
    }
    // Drain the callback queue even after a failed start with a null handle.
    // A completion signal can wake its caller before the block has returned.
    struct completion *completion = completion_create();
    if (completion == NULL) {
        quarantine("queue drain allocation failed");
        return false;
    }
    struct completion *drained = completion;
    dispatch_async(bridge->queue, ^{
        dispatch_semaphore_signal(drained->done);
        completion_release(drained);
    });
    bool empty = wait_for(completion->done);
    completion_release(completion);
    if (!empty) {
        quarantine("event queue drain timed out");
        return false;
    }
    destroy_bridge(bridge);
    return true;
}

static size_t batch_size(uint64_t advertised)
{
    if (advertised == 0) {
        return 1;
    }
    return advertised < KRUN_VMNET_MAX_BATCH_PACKETS
        ? (size_t)advertised
        : KRUN_VMNET_MAX_BATCH_PACKETS;
}

static int allocate_packet_batch(
    struct krun_vmnet_bridge *bridge,
    size_t count,
    uint8_t **buffers,
    struct iovec **iovs,
    struct vmpktdesc **packets)
{
    if (count > SIZE_MAX / bridge->max_packet_size) {
        return -ENOMEM;
    }
    *buffers = malloc(count * bridge->max_packet_size);
    *iovs = calloc(count, sizeof(**iovs));
    *packets = calloc(count, sizeof(**packets));
    if (*buffers == NULL || *iovs == NULL || *packets == NULL) {
        return -ENOMEM;
    }
    reset_packet_batch(bridge, *iovs, *packets, *buffers, count);
    return 0;
}

// Takes ownership of network (when non-NULL) and descriptor, including on failure.
static int32_t start_interface(
    vmnet_network_ref network,
    xpc_object_t descriptor,
    int *out_fd,
    void **out_bridge)
    __attribute__((availability(macos, introduced = 26.0)));

static int32_t start_interface(
    vmnet_network_ref network,
    xpc_object_t descriptor,
    int *out_fd,
    void **out_bridge)
{
    struct krun_vmnet_bridge *bridge = calloc(1, sizeof(*bridge));
    if (bridge == NULL) {
        if (network != NULL) {
            CFRelease(network);
        }
        xpc_release(descriptor);
        return -ENOMEM;
    }
    bridge->network = network;
    bridge->descriptor = descriptor;
    bridge->fd = -1;
    atomic_init(&bridge->stopping, false);
    bridge->queue = dispatch_queue_create("org.libkrun.vmnet", DISPATCH_QUEUE_SERIAL);
    bridge->tx_done = dispatch_semaphore_create(0);
    if (bridge->queue == NULL || bridge->tx_done == NULL) {
        destroy_bridge(bridge);
        return -ENOMEM;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) {
        int error = errno;
        destroy_bridge(bridge);
        return -error;
    }
    bridge->fd = sockets[1];
    int result = set_socket_options(sockets[0]);
    if (result == 0) {
        result = set_socket_options(sockets[1]);
    }
    if (result != 0) {
        close(sockets[0]);
        destroy_bridge(bridge);
        return result;
    }
    struct completion *completion = completion_create();
    if (completion == NULL) {
        close(sockets[0]);
        destroy_bridge(bridge);
        return -ENOMEM;
    }
    void (^started)(vmnet_return_t, xpc_object_t) = ^(vmnet_return_t status, xpc_object_t parameters) {
        completion->status = status;
        if (status == VMNET_SUCCESS && parameters != NULL) {
            completion->max_packet_size = xpc_dictionary_get_uint64(parameters, vmnet_max_packet_size_key);
            completion->read_max_packets = xpc_dictionary_get_uint64(parameters, vmnet_read_max_packets_key);
            completion->write_max_packets = xpc_dictionary_get_uint64(parameters, vmnet_write_max_packets_key);
        }
        dispatch_semaphore_signal(completion->done);
        completion_release(completion);
    };
    if (network != NULL) {
        bridge->interface = vmnet_interface_start_with_network(
            network, descriptor, bridge->queue, started);
    } else {
        bridge->interface = vmnet_start_interface(descriptor, bridge->queue, started);
    }
    bool completed = wait_for(completion->done);
    vmnet_return_t status = completed ? completion->status : VMNET_FAILURE;
    uint64_t max_packet_size = completed ? completion->max_packet_size : 0;
    uint64_t read_max_packets = completed ? completion->read_max_packets : 0;
    uint64_t write_max_packets = completed ? completion->write_max_packets : 0;
    completion_release(completion);
    if (!completed) {
        close(sockets[0]);
        // No packet callback/thread was installed. Keep framework state alive
        // for a late start callback rather than racing an incomplete start.
        quarantine("interface start timed out");
        return -ETIMEDOUT;
    }
    if (bridge->interface == NULL || status != VMNET_SUCCESS) {
        const char *operation = network != NULL
            ? "vmnet_interface_start_with_network"
            : "vmnet_start_interface";
        int32_t error = vmnet_framework_error(operation, status);
        close(sockets[0]);
        (void)stop_bridge(bridge);
        return error;
    }
    if (max_packet_size < 1514 || max_packet_size > KRUN_VMNET_MAX_FRAME_SIZE) {
        close(sockets[0]);
        (void)stop_bridge(bridge);
        return -EMSGSIZE;
    }
    bridge->max_packet_size = (size_t)max_packet_size;
    bridge->read_batch_size = batch_size(read_max_packets);
    bridge->write_batch_size = batch_size(write_max_packets);
    result = allocate_packet_batch(
        bridge, bridge->read_batch_size,
        &bridge->rx_buffers, &bridge->rx_iovs, &bridge->rx_packets);
    if (result == 0) {
        result = allocate_packet_batch(
            bridge, KRUN_VMNET_MAX_BATCH_PACKETS,
            &bridge->tx_buffers, &bridge->tx_iovs, &bridge->tx_packets);
    }
    if (result == 0) {
        bridge->socket_rx_buffer = malloc(KRUN_VMNET_MAX_FRAME_SIZE);
        if (bridge->socket_rx_buffer == NULL) {
            result = -ENOMEM;
        }
    }
    if (result != 0) {
        close(sockets[0]);
        (void)stop_bridge(bridge);
        return result;
    }
    status = vmnet_interface_set_event_callback(
        bridge->interface, VMNET_INTERFACE_PACKETS_AVAILABLE, bridge->queue,
        ^(interface_event_t event_id, xpc_object_t event) {
            if (event_id == VMNET_INTERFACE_PACKETS_AVAILABLE) {
                forward_packets_to_guest(bridge, event);
            }
        });
    if (status != VMNET_SUCCESS) {
        int32_t error = vmnet_framework_error("vmnet_interface_set_event_callback", status);
        close(sockets[0]);
        (void)stop_bridge(bridge);
        return error;
    }
    int error = pthread_create(&bridge->tx_thread, NULL, forward_packets_to_vmnet, bridge);
    if (error != 0) {
        close(sockets[0]);
        (void)stop_bridge(bridge);
        return -error;
    }
    bridge->tx_started = true;
    *out_fd = sockets[0];
    *out_bridge = bridge;
    return 0;
}

static int32_t start_network(
    vmnet_network_ref network, bool isolated, bool enable_offload, int *out_fd, void **out_bridge)
    __attribute__((availability(macos, introduced = 26.0)));

static int32_t start_network(
    vmnet_network_ref network, bool isolated, bool enable_offload, int *out_fd, void **out_bridge)
{
    xpc_object_t descriptor = xpc_dictionary_create(NULL, NULL, 0);
    if (descriptor == NULL) {
        CFRelease(network);
        return -ENOMEM;
    }
    xpc_dictionary_set_bool(descriptor, vmnet_allocate_mac_address_key, false);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_isolation_key, isolated);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_tso_key, enable_offload);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_checksum_offload_key, enable_offload);
    return start_interface(network, descriptor, out_fd, out_bridge);
}

static int32_t start_shared(
    const char *gateway, const char *netmask, bool enable_offload, int *out_fd, void **out_bridge)
    __attribute__((availability(macos, introduced = 26.0)));

static int32_t start_shared(
    const char *gateway, const char *netmask, bool enable_offload, int *out_fd, void **out_bridge)
{
    struct in_addr address, mask;
    if (inet_pton(AF_INET, gateway, &address) != 1 || inet_pton(AF_INET, netmask, &mask) != 1) {
        return -EINVAL;
    }
    uint32_t address_host = ntohl(address.s_addr);
    uint32_t mask_host = ntohl(mask.s_addr);
    uint32_t host_mask = ~mask_host;
    uint32_t host = address_host & host_mask;
    // A contiguous /1../30 network and an actual host address are required.
    if (mask.s_addr == 0 || host_mask < 3 || (host_mask & (host_mask + 1)) != 0
        || host == 0 || host == host_mask) {
        return -EINVAL;
    }

    // Use the long-standing vmnet_start_interface shared-mode API here rather
    // than reserving the subnet with vmnet_network_create(). A network_ref is
    // an exclusive reservation: creating one in every per-VM helper prevents a
    // second VM from joining the same Apple allocationOnly network. Shared-mode
    // interfaces with matching address settings are intentionally allowed to
    // coexist across VM processes.
    uint32_t network_host = address_host & mask_host;
    struct in_addr end_address = {.s_addr = htonl(network_host | (host_mask - 1))};
    char end[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &end_address, end, sizeof(end)) == NULL) {
        return -errno;
    }

    xpc_object_t descriptor = xpc_dictionary_create(NULL, NULL, 0);
    if (descriptor == NULL) {
        return -ENOMEM;
    }
    xpc_dictionary_set_uint64(descriptor, vmnet_operation_mode_key, VMNET_SHARED_MODE);
    xpc_dictionary_set_string(descriptor, vmnet_start_address_key, gateway);
    xpc_dictionary_set_string(descriptor, vmnet_end_address_key, end);
    xpc_dictionary_set_string(descriptor, vmnet_subnet_mask_key, netmask);
    xpc_dictionary_set_bool(descriptor, vmnet_allocate_mac_address_key, false);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_isolation_key, true);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_tso_key, enable_offload);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_checksum_offload_key, enable_offload);
    return start_interface(NULL, descriptor, out_fd, out_bridge);
}
#endif

int32_t krun_vmnet_start(
    const void *network_serialization, int enable_offload, int *out_fd, void **out_bridge)
{
    if (network_serialization == NULL || (enable_offload != 0 && enable_offload != 1)
        || out_fd == NULL || out_bridge == NULL) {
        return -EINVAL;
    }
    *out_fd = -1;
    *out_bridge = NULL;
#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (__builtin_available(macOS 26.0, *)) {
        vmnet_return_t status = VMNET_FAILURE;
        vmnet_network_ref network = vmnet_network_create_with_serialization((xpc_object_t)network_serialization, &status);
        if (network == NULL || status != VMNET_SUCCESS) {
            if (network != NULL) {
                CFRelease(network);
            }
            return vmnet_framework_error("vmnet_network_create_with_serialization", status);
        }
        return start_network(network, false, enable_offload != 0, out_fd, out_bridge);
    }
#endif
    return -ENOTSUP;
}

int32_t krun_vmnet_start_shared(
    const char *gateway, const char *netmask, int enable_offload, int *out_fd, void **out_bridge)
{
    if (gateway == NULL || netmask == NULL || (enable_offload != 0 && enable_offload != 1)
        || out_fd == NULL || out_bridge == NULL) {
        return -EINVAL;
    }
    *out_fd = -1;
    *out_bridge = NULL;
#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (__builtin_available(macOS 26.0, *)) {
        return start_shared(gateway, netmask, enable_offload != 0, out_fd, out_bridge);
    }
#endif
    return -ENOTSUP;
}

void krun_vmnet_stop(void *opaque)
{
#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (opaque != NULL) {
        (void)stop_bridge(opaque);
    }
#else
    (void)opaque;
#endif
}
