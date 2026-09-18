// SPDX-License-Identifier: Apache-2.0

#include <Availability.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
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

struct krun_vmnet_bridge {
    interface_ref interface;
    dispatch_queue_t queue;
    int fd;
    pthread_t tx_thread;
    size_t max_packet_size;
    atomic_bool stopping;
};

static int vmnet_status_to_errno(vmnet_return_t status)
{
    switch (status) {
    case VMNET_SUCCESS:
        return 0;
    case VMNET_INVALID_ARGUMENT:
        return EINVAL;
    case VMNET_INVALID_ACCESS:
        return EACCES;
    case VMNET_MEM_FAILURE:
        return ENOMEM;
    case VMNET_PACKET_TOO_BIG:
        return EMSGSIZE;
    case VMNET_SETUP_INCOMPLETE:
        return EAGAIN;
    default:
        return EIO;
    }
}

static void set_socket_options(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    int fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags >= 0) {
        (void)fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC);
    }

    const int no_sigpipe = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));

    const int rcvbuf = KRUN_VMNET_SOCKET_RCVBUF;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    const int sndbuf = KRUN_VMNET_MAX_FRAME_SIZE;
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
}

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000

static void forward_packets_to_guest(struct krun_vmnet_bridge *bridge, xpc_object_t event)
{
    if (atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        return;
    }

    uint64_t available = xpc_dictionary_get_uint64(event, vmnet_estimated_packets_available_key);
    if (available == 0) {
        available = 1;
    }

    uint8_t *buffer = malloc(bridge->max_packet_size);
    if (buffer == NULL) {
        return;
    }

    for (uint64_t i = 0; i < available; i++) {
        struct iovec iov = {
            .iov_base = buffer,
            .iov_len = bridge->max_packet_size,
        };
        struct vmpktdesc packet = {
            .vm_pkt_size = bridge->max_packet_size,
            .vm_pkt_iov = &iov,
            .vm_pkt_iovcnt = 1,
            .vm_flags = 0,
        };
        int count = 1;
        vmnet_return_t status = vmnet_read(bridge->interface, &packet, &count);
        if (status != VMNET_SUCCESS || count != 1) {
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
    uint8_t *buffer = malloc(bridge->max_packet_size);
    if (buffer == NULL) {
        return NULL;
    }

    while (!atomic_load_explicit(&bridge->stopping, memory_order_relaxed)) {
        struct pollfd pollfd = {
            .fd = bridge->fd,
            .events = POLLIN,
        };
        int ready = poll(&pollfd, 1, 250);
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

        for (;;) {
            ssize_t length = recv(bridge->fd, buffer, bridge->max_packet_size, 0);
            if (length < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                atomic_store_explicit(&bridge->stopping, true, memory_order_relaxed);
                break;
            }
            if (length == 0) {
                break;
            }

            struct iovec iov = {
                .iov_base = buffer,
                .iov_len = (size_t)length,
            };
            struct vmpktdesc packet = {
                .vm_pkt_size = (size_t)length,
                .vm_pkt_iov = &iov,
                .vm_pkt_iovcnt = 1,
                .vm_flags = 0,
            };
            int count = 1;
            (void)vmnet_write(bridge->interface, &packet, &count);
        }
    }

    free(buffer);
    return NULL;
}

static void stop_interface(struct krun_vmnet_bridge *bridge)
{
    if (bridge->interface == NULL) {
        return;
    }

    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    vmnet_return_t status = vmnet_stop_interface(
        bridge->interface,
        bridge->queue,
        ^(vmnet_return_t stop_status) {
            (void)stop_status;
            dispatch_semaphore_signal(done);
        });
    if (status == VMNET_SUCCESS) {
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    }
    dispatch_release(done);
    bridge->interface = NULL;
}

#endif

int32_t krun_vmnet_start(
    const void *network_serialization,
    int *out_fd,
    void **out_bridge)
{
    if (network_serialization == NULL || out_fd == NULL || out_bridge == NULL) {
        return -EINVAL;
    }

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (__builtin_available(macOS 26.0, *)) {
        xpc_object_t serialization = (xpc_object_t)network_serialization;

        struct krun_vmnet_bridge *bridge = calloc(1, sizeof(*bridge));
        if (bridge == NULL) {
            return -ENOMEM;
        }
        bridge->fd = -1;
        atomic_init(&bridge->stopping, false);

        int sockets[2] = {-1, -1};
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) {
            int error = errno;
            free(bridge);
            return -error;
        }
        set_socket_options(sockets[0]);
        set_socket_options(sockets[1]);
        bridge->fd = sockets[1];

        vmnet_return_t status = VMNET_FAILURE;
        vmnet_network_ref network = vmnet_network_create_with_serialization(serialization, &status);
        if (network == NULL || status != VMNET_SUCCESS) {
            close(sockets[0]);
            close(sockets[1]);
            free(bridge);
            return -vmnet_status_to_errno(status);
        }

        bridge->queue = dispatch_queue_create("org.libkrun.vmnet", DISPATCH_QUEUE_SERIAL);
        xpc_object_t interface_desc = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_bool(interface_desc, vmnet_allocate_mac_address_key, false);
        xpc_dictionary_set_bool(interface_desc, vmnet_enable_tso_key, false);
        xpc_dictionary_set_bool(interface_desc, vmnet_enable_checksum_offload_key, false);

        dispatch_semaphore_t started = dispatch_semaphore_create(0);
        __block vmnet_return_t start_status = VMNET_FAILURE;
        __block uint64_t max_packet_size = 0;
        bridge->interface = vmnet_interface_start_with_network(
            network,
            interface_desc,
            bridge->queue,
            ^(vmnet_return_t callback_status, xpc_object_t interface_params) {
                start_status = callback_status;
                if (callback_status == VMNET_SUCCESS && interface_params != NULL) {
                    max_packet_size = xpc_dictionary_get_uint64(
                        interface_params,
                        vmnet_max_packet_size_key);
                }
                dispatch_semaphore_signal(started);
            });

        dispatch_semaphore_wait(started, DISPATCH_TIME_FOREVER);
        dispatch_release(started);
        xpc_release(interface_desc);
        CFRelease(network);

        if (bridge->interface == NULL || start_status != VMNET_SUCCESS) {
            close(sockets[0]);
            close(sockets[1]);
            if (bridge->queue != NULL) {
                dispatch_release(bridge->queue);
            }
            free(bridge);
            return -vmnet_status_to_errno(start_status);
        }

        if (max_packet_size == 0 || max_packet_size > KRUN_VMNET_MAX_FRAME_SIZE) {
            max_packet_size = KRUN_VMNET_MAX_FRAME_SIZE;
        }
        bridge->max_packet_size = (size_t)max_packet_size;

        status = vmnet_interface_set_event_callback(
            bridge->interface,
            VMNET_INTERFACE_PACKETS_AVAILABLE,
            bridge->queue,
            ^(interface_event_t event_id, xpc_object_t event) {
                if (event_id == VMNET_INTERFACE_PACKETS_AVAILABLE) {
                    forward_packets_to_guest(bridge, event);
                }
            });
        if (status != VMNET_SUCCESS) {
            int error = vmnet_status_to_errno(status);
            stop_interface(bridge);
            close(sockets[0]);
            close(sockets[1]);
            dispatch_release(bridge->queue);
            free(bridge);
            return -error;
        }

        int pthread_status = pthread_create(
            &bridge->tx_thread,
            NULL,
            forward_packets_to_vmnet,
            bridge);
        if (pthread_status != 0) {
            stop_interface(bridge);
            close(sockets[0]);
            close(sockets[1]);
            dispatch_release(bridge->queue);
            free(bridge);
            return -pthread_status;
        }

        *out_fd = sockets[0];
        *out_bridge = bridge;
        return 0;
    }
#endif

    return -ENOTSUP;
}

void krun_vmnet_stop(void *opaque)
{
    if (opaque == NULL) {
        return;
    }

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (__builtin_available(macOS 26.0, *)) {
        struct krun_vmnet_bridge *bridge = opaque;
        atomic_store_explicit(&bridge->stopping, true, memory_order_relaxed);
        (void)pthread_join(bridge->tx_thread, NULL);
        stop_interface(bridge);
        if (bridge->fd >= 0) {
            close(bridge->fd);
        }
        if (bridge->queue != NULL) {
            dispatch_release(bridge->queue);
        }
        free(bridge);
        return;
    }
#endif

    (void)opaque;
}
