#pragma once
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <sys/uio.h>
#include <xpc/xpc.h>
typedef int vmnet_return_t;
typedef int interface_event_t;
typedef struct fake_network *vmnet_network_ref;
typedef struct fake_configuration *vmnet_network_configuration_ref;
typedef struct fake_interface *interface_ref;
enum { VMNET_FAILURE = 0, VMNET_SUCCESS = 1, VMNET_INVALID_ARGUMENT, VMNET_INVALID_ACCESS,
       VMNET_MEM_FAILURE, VMNET_PACKET_TOO_BIG, VMNET_SETUP_INCOMPLETE, VMNET_BUFFER_EXHAUSTED,
       VMNET_TOO_MANY_PACKETS, VMNET_NOT_AUTHORIZED, VMNET_SHARING_SERVICE_BUSY };
enum { VMNET_SHARED_MODE = 1, VMNET_INTERFACE_PACKETS_AVAILABLE = 1 };
#define vmnet_allocate_mac_address_key "allocate_mac"
#define vmnet_enable_isolation_key "isolation"
#define vmnet_enable_tso_key "tso"
#define vmnet_enable_checksum_offload_key "checksum"
#define vmnet_max_packet_size_key "max_packet"
#define vmnet_operation_mode_key "operation_mode"
#define vmnet_start_address_key "start_address"
#define vmnet_end_address_key "end_address"
#define vmnet_subnet_mask_key "subnet_mask"
#define vmnet_estimated_packets_available_key "estimated"
struct vmpktdesc { size_t vm_pkt_size; struct iovec *vm_pkt_iov; unsigned vm_pkt_iovcnt; unsigned vm_flags; };
vmnet_network_configuration_ref vmnet_network_configuration_create(int mode, vmnet_return_t *status);
void vmnet_network_configuration_disable_dhcp(vmnet_network_configuration_ref configuration);
vmnet_return_t vmnet_network_configuration_set_ipv4_subnet(vmnet_network_configuration_ref configuration, const struct in_addr *address, const struct in_addr *mask);
vmnet_network_ref vmnet_network_create(vmnet_network_configuration_ref configuration, vmnet_return_t *status);
vmnet_network_ref vmnet_network_create_with_serialization(xpc_object_t object, vmnet_return_t *status);
interface_ref vmnet_start_interface(xpc_object_t descriptor, dispatch_queue_t queue, void (^callback)(vmnet_return_t, xpc_object_t));
void vmnet_network_get_ipv4_subnet(vmnet_network_ref network, struct in_addr *address, struct in_addr *mask);
interface_ref vmnet_interface_start_with_network(vmnet_network_ref network, xpc_object_t descriptor, dispatch_queue_t queue, void (^callback)(vmnet_return_t, xpc_object_t));
vmnet_return_t vmnet_interface_set_event_callback(interface_ref interface, interface_event_t events, dispatch_queue_t queue, void (^callback)(interface_event_t, xpc_object_t));
vmnet_return_t vmnet_stop_interface(interface_ref interface, dispatch_queue_t queue, void (^callback)(vmnet_return_t));
vmnet_return_t vmnet_read(interface_ref interface, struct vmpktdesc *packets, int *count);
vmnet_return_t vmnet_write(interface_ref interface, struct vmpktdesc *packets, int *count);
