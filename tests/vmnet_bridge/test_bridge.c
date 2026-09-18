// SPDX-License-Identifier: Apache-2.0
// Executes the production C bridge with a fake vmnet framework, real sockets,
// pthreads, dispatch queues, and Blocks. Does not emulate HVF or macOS privileges.
#include <assert.h>
#include <string.h>
#include <Block.h>
#include "../../src/libkrun/src/vmnet.c"

struct fake_xpc {
    bool isolation;
    bool allocate_mac;
    bool tso;
    bool checksum;
    uint64_t size;
    uint64_t mode;
    char start[INET_ADDRSTRLEN];
    char end[INET_ADDRSTRLEN];
    char mask[INET_ADDRSTRLEN];
};
struct fake_configuration { struct in_addr address, mask; bool dhcp_disabled; };
struct fake_network { struct in_addr address, mask; };
struct fake_interface { void (^event)(interface_event_t, xpc_object_t); dispatch_queue_t queue; };
static const char *scenario;
static atomic_int writes;
static atomic_int reads_pending;
static atomic_int network_releases;
static atomic_int network_create_calls;
static atomic_int shared_start_calls;
static vmnet_network_ref owned_network;
static interface_ref active_interface;
static bool is(const char *name) { return strcmp(scenario, name) == 0; }

void CFRelease(const void *object)
{
    if (object == owned_network) { atomic_fetch_add(&network_releases, 1); owned_network = NULL; }
    free((void *)object);
}
xpc_object_t xpc_dictionary_create(const char *const *keys, const xpc_object_t *values, size_t count)
{ (void)keys; (void)values; (void)count; return calloc(1, sizeof(struct fake_xpc)); }
void xpc_dictionary_set_bool(xpc_object_t object, const char *key, bool value)
{
    if (strcmp(key, "isolation") == 0) object->isolation = value;
    else if (strcmp(key, "allocate_mac") == 0) object->allocate_mac = value;
    else if (strcmp(key, "tso") == 0) object->tso = value;
    else if (strcmp(key, "checksum") == 0) object->checksum = value;
    else abort();
}
void xpc_dictionary_set_uint64(xpc_object_t object, const char *key, uint64_t value)
{
    assert(strcmp(key, "operation_mode") == 0);
    object->mode = value;
}
void xpc_dictionary_set_string(xpc_object_t object, const char *key, const char *value)
{
    char *target = NULL;
    if (strcmp(key, "start_address") == 0) target = object->start;
    else if (strcmp(key, "end_address") == 0) target = object->end;
    else if (strcmp(key, "subnet_mask") == 0) target = object->mask;
    else abort();
    assert(strlen(value) < INET_ADDRSTRLEN);
    strcpy(target, value);
}
uint64_t xpc_dictionary_get_uint64(xpc_object_t object, const char *key)
{ (void)key; return object->size; }
void xpc_release(xpc_object_t object) { free(object); }
vmnet_network_configuration_ref vmnet_network_configuration_create(int mode, vmnet_return_t *status)
{
    assert(mode == VMNET_SHARED_MODE);
    *status = is("permission") ? VMNET_INVALID_ACCESS : VMNET_SUCCESS;
    return *status == VMNET_SUCCESS ? calloc(1, sizeof(struct fake_configuration)) : NULL;
}
void vmnet_network_configuration_disable_dhcp(vmnet_network_configuration_ref config) { config->dhcp_disabled = true; }
vmnet_return_t vmnet_network_configuration_set_ipv4_subnet(vmnet_network_configuration_ref config, const struct in_addr *address, const struct in_addr *mask)
{
    assert(config->dhcp_disabled);
    config->address = *address; config->mask = *mask;
    return is("subnet_failure") ? VMNET_INVALID_ARGUMENT : VMNET_SUCCESS;
}
vmnet_network_ref vmnet_network_create(vmnet_network_configuration_ref config, vmnet_return_t *status)
{
    assert(config->dhcp_disabled);
    int call = atomic_fetch_add(&network_create_calls, 1) + 1;
    if (is("network_busy") || (is("network_busy_once") && call == 1)) {
        *status = VMNET_SHARING_SERVICE_BUSY;
        return NULL;
    }
    if (is("network_setup_once") && call == 1) {
        *status = VMNET_SETUP_INCOMPLETE;
        return NULL;
    }
    if (is("network_not_authorized")) {
        *status = VMNET_NOT_AUTHORIZED;
        return NULL;
    }
    *status = VMNET_SUCCESS;
    if (is("null_network_success")) return NULL;
    owned_network = calloc(1, sizeof(struct fake_network));
    owned_network->address = config->address; owned_network->mask = config->mask;
    return owned_network;
}
vmnet_network_ref vmnet_network_create_with_serialization(xpc_object_t object, vmnet_return_t *status)
{
    (void)object;
    if (is("serialized_not_authorized")) { *status = VMNET_NOT_AUTHORIZED; return NULL; }
    *status = VMNET_SUCCESS;
    owned_network = calloc(1, sizeof(struct fake_network));
    return owned_network;
}
void vmnet_network_get_ipv4_subnet(vmnet_network_ref network, struct in_addr *address, struct in_addr *mask)
{
    *address = network->address; *mask = network->mask;
    if (is("subnet_mismatch")) address->s_addr ^= 1;
}
static interface_ref fake_start(xpc_object_t descriptor, dispatch_queue_t queue,
                                void (^callback)(vmnet_return_t, xpc_object_t))
{
    active_interface = is("null_interface_success") ? NULL : calloc(1, sizeof(struct fake_interface));
    if (active_interface) active_interface->queue = queue;
    int64_t delay = is("late_start") ? 500 * NSEC_PER_MSEC : 0;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delay), queue, ^{
        assert(!descriptor->allocate_mac); // Descriptor must outlive asynchronous start.
        struct fake_xpc parameters = {.size = is("invalid_packet_size") ? 0 : 2048};
        callback((is("start_failure") || is("permission")) ? VMNET_INVALID_ACCESS : VMNET_SUCCESS, &parameters);
    });
    return active_interface;
}
interface_ref vmnet_interface_start_with_network(vmnet_network_ref network, xpc_object_t descriptor,
                                                dispatch_queue_t queue, void (^callback)(vmnet_return_t, xpc_object_t))
{
    assert(network == owned_network);
    assert(!descriptor->isolation);
    assert(!descriptor->allocate_mac && !descriptor->tso && !descriptor->checksum);
    return fake_start(descriptor, queue, callback);
}
interface_ref vmnet_start_interface(xpc_object_t descriptor, dispatch_queue_t queue,
                                   void (^callback)(vmnet_return_t, xpc_object_t))
{
    atomic_fetch_add(&shared_start_calls, 1);
    assert(descriptor->mode == VMNET_SHARED_MODE);
    assert(descriptor->isolation);
    assert(!descriptor->allocate_mac && !descriptor->tso && !descriptor->checksum);
    assert(strcmp(descriptor->start, "192.168.200.1") == 0);
    assert(strcmp(descriptor->end, "192.168.200.254") == 0);
    assert(strcmp(descriptor->mask, "255.255.255.0") == 0);
    return fake_start(descriptor, queue, callback);
}
vmnet_return_t vmnet_interface_set_event_callback(interface_ref interface, interface_event_t events,
                                                 dispatch_queue_t queue, void (^callback)(interface_event_t, xpc_object_t))
{
    assert(events == VMNET_INTERFACE_PACKETS_AVAILABLE && queue == interface->queue);
    if (is("event_failure")) return VMNET_FAILURE;
    interface->event = Block_copy(callback);
    return VMNET_SUCCESS;
}
vmnet_return_t vmnet_stop_interface(interface_ref interface, dispatch_queue_t queue, void (^callback)(vmnet_return_t))
{
    int64_t delay = is("late_stop") || is("stop_submit_failure") ? 500 * NSEC_PER_MSEC : 0;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delay), queue, ^{
        if (interface->event) Block_release(interface->event);
        free(interface);
        callback(VMNET_SUCCESS);
    });
    return is("stop_submit_failure") ? VMNET_FAILURE : VMNET_SUCCESS;
}
vmnet_return_t vmnet_read(interface_ref interface, struct vmpktdesc *packets, int *count)
{
    (void)interface;
    if (atomic_load(&reads_pending) > 0) {
        atomic_fetch_sub(&reads_pending, 1);
        memcpy(packets->vm_pkt_iov->iov_base, "native-reply", 12);
        packets->vm_pkt_size = 12; *count = 1;
    } else { *count = 0; }
    return VMNET_SUCCESS;
}
vmnet_return_t vmnet_write(interface_ref interface, struct vmpktdesc *packets, int *count)
{
    (void)interface;
    assert(*count == 1 && packets->vm_pkt_size > 0);
    atomic_fetch_add(&writes, 1);
    return VMNET_SUCCESS;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    scenario = argv[1];
    int fd = 99;
    void *bridge = (void *)1;
    if (is("shared_pair")) {
        int fd2 = -1;
        void *bridge2 = NULL;
        assert(krun_vmnet_start_shared("192.168.200.1", "255.255.255.0", &fd, &bridge) == 0);
        assert(krun_vmnet_start_shared("192.168.200.1", "255.255.255.0", &fd2, &bridge2) == 0);
        assert(atomic_load(&shared_start_calls) == 2);
        assert(atomic_load(&network_create_calls) == 0);
        close(fd);
        close(fd2);
        krun_vmnet_stop(bridge);
        krun_vmnet_stop(bridge2);
        puts("PASS: shared_pair");
        return 0;
    }
    if (is("invalid_arguments")) {
        assert(krun_vmnet_start_shared(NULL, "255.255.255.0", &fd, &bridge) == -EINVAL);
        const char *bad_gateway[] = {"garbage", "192.168.200.0", "192.168.200.255", "256.1.1.1"};
        for (unsigned i = 0; i < sizeof(bad_gateway) / sizeof(bad_gateway[0]); i++) {
            assert(krun_vmnet_start_shared(bad_gateway[i], "255.255.255.0", &fd, &bridge) == -EINVAL);
            assert(fd == -1 && bridge == NULL);
        }
        assert(krun_vmnet_start_shared("192.168.200.1", "255.0.255.0", &fd, &bridge) == -EINVAL);
        assert(krun_vmnet_start_shared("192.168.200.1", "255.255.255.255", &fd, &bridge) == -EINVAL);
        assert(krun_vmnet_start_shared("192.168.200.1", "0.0.0.0", &fd, &bridge) == -EINVAL);
        puts("PASS: invalid_arguments");
        return 0;
    }
    bool serialized = is("serialized") || is("serialized_not_authorized");
    int result = serialized ? krun_vmnet_start((void *)1, &fd, &bridge)
                            : krun_vmnet_start_shared("192.168.200.1", "255.255.255.0", &fd, &bridge);
    if (is("permission") || is("start_failure")) assert(result == -EACCES);
    else if (is("serialized_not_authorized")) assert(result == -EPERM);
    else if (is("null_interface_success") || is("event_failure")) assert(result == -EIO);
    else if (is("invalid_packet_size")) assert(result == -EMSGSIZE);
    else if (is("late_start")) assert(result == -ETIMEDOUT);
    else assert(result == 0);
    if (!serialized) assert(atomic_load(&network_create_calls) == 0);
    if (result != 0) {
        assert(fd == -1 && bridge == NULL);
        if (is("late_start")) usleep(650000); // Exercise callback after caller returned; ASan must remain quiet.
    } else {
        assert(fd >= 0 && bridge != NULL);
        assert((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
        assert((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
        assert(send(fd, "native-frame", 12, 0) == 12);
        for (int i = 0; i < 100 && atomic_load(&writes) == 0; i++) usleep(1000);
        assert(atomic_load(&writes) == 1);
        atomic_store(&reads_pending, 1);
        dispatch_sync(active_interface->queue, ^{
            struct fake_xpc event = {.size = 1};
            active_interface->event(VMNET_INTERFACE_PACKETS_AVAILABLE, &event);
        });
        char data[32];
        assert(recv(fd, data, sizeof(data), 0) == 12 && memcmp(data, "native-reply", 12) == 0);
        if (is("truncated_frame")) {
            char huge[4096] = {0};
            assert(send(fd, huge, sizeof(huge), 0) == sizeof(huge));
            usleep(50000);
            assert(atomic_load(&writes) == 1); // Truncation must not reach vmnet_write.
        }
        close(fd);
        krun_vmnet_stop(bridge);
        if (is("late_stop") || is("stop_submit_failure")) {
            usleep(650000);
            assert(atomic_load(&network_releases) == 0); // Quarantined until process exit.
        } else {
            assert(atomic_load(&network_releases) == (serialized ? 1 : 0));
        }
    }
    printf("PASS: %s\n", scenario);
    return 0;
}
