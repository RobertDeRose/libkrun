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
    uint8_t *tx_buffer;
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

static void forward_packets_to_guest(struct krun_vmnet_bridge *bridge, xpc_object_t event)
{
    if (atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        return;
    }
    uint64_t available = xpc_dictionary_get_uint64(event, vmnet_estimated_packets_available_key);
    // Check stopping between packets rather than capping the advertised batch:
    // leaving queued frames unread can lose an edge-triggered notification.
    available = available == 0 ? 1 : available;
    uint8_t *buffer = malloc(bridge->max_packet_size);
    if (buffer == NULL) {
        return;
    }
    for (uint64_t i = 0; i < available; i++) {
        if (atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
            break;
        }
        struct iovec iov = {.iov_base = buffer, .iov_len = bridge->max_packet_size};
        struct vmpktdesc packet = {
            .vm_pkt_size = bridge->max_packet_size, .vm_pkt_iov = &iov,
            .vm_pkt_iovcnt = 1, .vm_flags = 0,
        };
        int count = 1;
        vmnet_return_t status = vmnet_read(bridge->interface, &packet, &count);
        if (status != VMNET_SUCCESS || count != 1 || packet.vm_pkt_size > bridge->max_packet_size) {
            break;
        }
        ssize_t written = send(bridge->fd, buffer, packet.vm_pkt_size, 0);
        if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) {
            break;
        }
    }
    free(buffer);
}

static void *forward_packets_to_vmnet(void *opaque)
{
    struct krun_vmnet_bridge *bridge = opaque;
    uint8_t *buffer = bridge->tx_buffer;
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
            struct iovec iov = {.iov_base = buffer, .iov_len = bridge->max_packet_size};
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
            iov.iov_len = (size_t)length;
            struct vmpktdesc packet = {
                .vm_pkt_size = (size_t)length, .vm_pkt_iov = &iov,
                .vm_pkt_iovcnt = 1, .vm_flags = 0,
            };
            int count = 1;
            (void)vmnet_write(bridge->interface, &packet, &count);
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
    free(bridge->tx_buffer);
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
    bridge->tx_buffer = malloc(bridge->max_packet_size);
    if (bridge->tx_buffer == NULL) {
        close(sockets[0]);
        (void)stop_bridge(bridge);
        return -ENOMEM;
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

static int32_t start_network(vmnet_network_ref network, bool isolated, int *out_fd, void **out_bridge)
    __attribute__((availability(macos, introduced = 26.0)));

static int32_t start_network(vmnet_network_ref network, bool isolated, int *out_fd, void **out_bridge)
{
    xpc_object_t descriptor = xpc_dictionary_create(NULL, NULL, 0);
    if (descriptor == NULL) {
        CFRelease(network);
        return -ENOMEM;
    }
    xpc_dictionary_set_bool(descriptor, vmnet_allocate_mac_address_key, false);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_isolation_key, isolated);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_tso_key, false);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_checksum_offload_key, false);
    return start_interface(network, descriptor, out_fd, out_bridge);
}

static int32_t start_shared(const char *gateway, const char *netmask, int *out_fd, void **out_bridge)
    __attribute__((availability(macos, introduced = 26.0)));

static int32_t start_shared(const char *gateway, const char *netmask, int *out_fd, void **out_bridge)
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
    xpc_dictionary_set_bool(descriptor, vmnet_enable_tso_key, false);
    xpc_dictionary_set_bool(descriptor, vmnet_enable_checksum_offload_key, false);
    return start_interface(NULL, descriptor, out_fd, out_bridge);
}
#endif

int32_t krun_vmnet_start(const void *network_serialization, int *out_fd, void **out_bridge)
{
    if (network_serialization == NULL || out_fd == NULL || out_bridge == NULL) {
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
        return start_network(network, false, out_fd, out_bridge);
    }
#endif
    return -ENOTSUP;
}

int32_t krun_vmnet_start_shared(const char *gateway, const char *netmask, int *out_fd, void **out_bridge)
{
    if (gateway == NULL || netmask == NULL || out_fd == NULL || out_bridge == NULL) {
        return -EINVAL;
    }
    *out_fd = -1;
    *out_bridge = NULL;
#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (__builtin_available(macOS 26.0, *)) {
        return start_shared(gateway, netmask, out_fd, out_bridge);
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
