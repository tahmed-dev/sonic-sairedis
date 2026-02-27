#include "SwitchVppUtils.h"
#include "SwitchVpp.h"
#include "SaiObjectDB.h"
#include "TunnelManager.h"
#include "IpVrfInfo.h"

#include "meta/sai_serialize.h"

#include "swss/logger.h"

#include "vppxlate/SaiVppXlate.h"

#include <arpa/inet.h>

using namespace saivs;

#define CHECK_STATUS_W_MSG(status, msg, ...) {                                  \
    sai_status_t _status = (status);                            \
    if (_status != SAI_STATUS_SUCCESS) { \
        char buffer[512]; \
        snprintf(buffer, 512, msg, ##__VA_ARGS__); \
        SWSS_LOG_ERROR("%s: status %d", buffer, status); \
        return _status; } }

TunnelManager::TunnelManager(SwitchVpp* switch_db): m_switch_db(switch_db)
{
    SWSS_LOG_ENTER();

    m_router_mac = {0, 0, 0, 0, 0, 1};
    m_vxlan_port = 4789;
}

const std::array<uint8_t, 6>&
TunnelManager::get_router_mac() const
{
    SWSS_LOG_ENTER();

    return m_router_mac;
}

void
TunnelManager::set_router_mac(const sai_attribute_t* attr)
{
    SWSS_LOG_ENTER();

    for (int i = 0; i < 6; ++i) {
        m_router_mac[i] = attr->value.mac[i];
    }
}

void
TunnelManager::set_vxlan_port(const sai_attribute_t* attr)
{
    SWSS_LOG_ENTER();

    m_vxlan_port = attr->value.u16;
}
/**
 * VxLAN tunnel is created in response to the creation of a tunnel encap nexthop entry. This assumes VxLAN tunnel is bidirectional and symmetric.
 * The local VTEP sends packet through the tunnel to the remote VTEP. The remote VTEP sends packet back to the local VTEP through the same tunnel with the same VNI.
 * Here is the VS config to be programmed in response to the creation of a tunnel encap nexthop entry:
 *
 * create vxlan tunnel src 1.0.0.1 dst 1.0.0.2 vni 3000
 * ip neighbor vxlan_tunnel0 1.0.0.2 00:00:00:00:00:01 no-fib-entry
 * ip route add 100.1.1.0/24 via 1.0.0.2 vxlan_tunnel0
 *
 * bvi create mac 00:00:00:00:00:01
 * set interface state bvi0 up
 * set interface ip address bvi0 0.0.0.2/32
 * set interface l2 bridge vxlan_tunnel0 3000 1
 * set interface l2 bridge bvi0 3000 bvi
 *
 * corresponding to below sonic config
 *   In CONFIG_DB
 *   "VXLAN_TUNNEL": {
 *        "test": {
 *           "src_ip": "1.0.0.1"
 *       }
 *   }
 *  "VNET": {
 *       "Vnet1": {
 *           "peer_list": "",
 *           "scope": "default",
 *           "vni": "3000",
 *           "vxlan_tunnel": "test"
 *       },
 *   }
 *   In APPL_DB
 *   "VNET_ROUTE_TUNNEL_TABLE:Vnet1:100.1.1.0/24":
 *         {
 *       "endpoint": "1.0.0.2"
 *         }
 */
sai_status_t
TunnelManager::tunnel_encap_nexthop_action(
                    _In_ const SaiObject* tunnel_nh_obj,
                    _In_ Action action)
{
    SWSS_LOG_ENTER();

    sai_attribute_t              attr;
    sai_ip_address_t             src_ip;
    sai_ip_address_t             dst_ip;
    std::unordered_map<u_int32_t, std::shared_ptr<IpVrfInfo>> vni_to_vrf_map;
    sai_object_id_t              object_id;

    SWSS_LOG_DEBUG("tunnel_encap_nexthop_action %s %s",
        action == Action::CREATE ? "CREATE" : "DELETE", tunnel_nh_obj->get_id().c_str());
    sai_deserialize_object_id(tunnel_nh_obj->get_id(), object_id);
    auto tunnel_obj = tunnel_nh_obj->get_linked_object(SAI_OBJECT_TYPE_TUNNEL, SAI_NEXT_HOP_ATTR_TUNNEL_ID);
    if (tunnel_obj == nullptr) {
        return SAI_STATUS_FAILURE;
    }
    attr.id = SAI_TUNNEL_ATTR_TYPE;
    CHECK_STATUS_W_MSG(tunnel_obj->get_attr(attr), "Missing SAI_TUNNEL_ATTR_TYPE in tunnel obj");

    if (attr.value.s32 != SAI_TUNNEL_TYPE_VXLAN) {
        SWSS_LOG_ERROR("Unsupported tunnel encap type %d in %s", attr.value.s32,
                        tunnel_obj->get_id().c_str());
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    attr.id = SAI_TUNNEL_ATTR_ENCAP_SRC_IP;
    CHECK_STATUS_W_MSG(tunnel_obj->get_attr(attr), "Missing SAI_TUNNEL_ATTR_ENCAP_SRC_IP in tunnel obj");
    // SAI_TUNNEL_ATTR_ENCAP_TTL_MODE and SAI_TUNNEL_ATTR_ENCAP_TTL_VAL are not supported in vpp
    src_ip = attr.value.ipaddr;

    attr.id = SAI_NEXT_HOP_ATTR_IP;
    CHECK_STATUS_W_MSG(tunnel_nh_obj->get_attr(attr), "Missing SAI_NEXT_HOP_ATTR_IP in %s", tunnel_nh_obj->get_id().c_str());

    dst_ip = attr.value.ipaddr;

    // Iterate tunnel encap mapper
    auto tunnel_encap_mappers = tunnel_obj->get_linked_objects(SAI_OBJECT_TYPE_TUNNEL_MAP, SAI_TUNNEL_ATTR_ENCAP_MAPPERS);

    for (auto tunnel_encap_mapper : tunnel_encap_mappers) {
        attr.id = SAI_TUNNEL_MAP_ATTR_TYPE;
        CHECK_STATUS_W_MSG(tunnel_encap_mapper->get_attr(attr),
                "Missing SAI_TUNNEL_MAP_ATTR_TYPE in %s",
                tunnel_encap_mapper->get_id().c_str());
        if (attr.value.s32 != SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI) {
            continue;
        }

        auto tunnel_encap_mapper_entries = tunnel_encap_mapper->get_child_objs(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY);
        if (tunnel_encap_mapper_entries == nullptr) {
            SWSS_LOG_DEBUG("Empty tunnel_encap_mapper table. OID %s",
                tunnel_encap_mapper->get_id().c_str());
            continue;
        }
        for (auto pair : *tunnel_encap_mapper_entries) {
            auto tunnel_encap_mapper_entry = pair.second;
            vpp_vxlan_tunnel_t req;
            u_int32_t tunnel_vni;
            TunnelVPPData tunnel_data;

            memset(&req, 0, sizeof(req));
            req.dst_port = m_vxlan_port;
            req.src_port = m_vxlan_port;
            req.instance = ~0;
            sai_ip_address_t_to_vpp_ip_addr_t(src_ip, req.src_address);
            sai_ip_address_t_to_vpp_ip_addr_t(dst_ip, req.dst_address);
            req.decap_next_index = ~0;

            attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE;
            CHECK_STATUS_W_MSG(tunnel_encap_mapper_entry->get_attr(attr),
                "Missing SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY in %s",
                tunnel_encap_mapper_entry->get_id().c_str());
            tunnel_vni = attr.value.u32;

            attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY;
            CHECK_STATUS_W_MSG(tunnel_encap_mapper_entry->get_attr(attr),
                    "Missing SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY in %s",
                    tunnel_encap_mapper_entry->get_id().c_str());

            auto ip_vrf = m_switch_db->vpp_get_ip_vrf(attr.value.oid);
            if (!ip_vrf) {
                SWSS_LOG_ERROR("Failed to find VR from SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY in %s",
                    tunnel_encap_mapper_entry->get_id().c_str());
                return SAI_STATUS_FAILURE;
            }
            vni_to_vrf_map[tunnel_vni] = ip_vrf;
            tunnel_data.ip_vrf = ip_vrf;
            req.vni = tunnel_vni;

            if (action == Action::CREATE) {
                if (create_vpp_vxlan_encap(req, tunnel_data) != SAI_STATUS_SUCCESS) {
                    SWSS_LOG_ERROR("Failed to create vxlan encap for %s",
                        tunnel_nh_obj->get_id().c_str());
                    return SAI_STATUS_FAILURE;
                }

                /* Skip decap if this tunnel was reused from boot-time L3 setup —
                 * vpp_l3_vxlan_tunnel_add already bound it to the VRF. */
                auto existing = find_existing_vxlan_tunnel(req);
                if (existing.first && existing.second == tunnel_data.sw_if_index) {
                    SWSS_LOG_NOTICE("Reused L3 tunnel sw_if_index %d, skipping decap setup",
                            tunnel_data.sw_if_index);
                } else if (create_vpp_vxlan_decap(tunnel_data) != SAI_STATUS_SUCCESS) {
                    SWSS_LOG_ERROR("Failed to create vxlan decap for %s",
                        tunnel_nh_obj->get_id().c_str());
                    remove_vpp_vxlan_encap(req, tunnel_data);
                    return SAI_STATUS_FAILURE;
                }
                m_tunnel_encap_nexthop_map[object_id] = tunnel_data;

            } else if (action == Action::DELETE) {
                auto encap_map_it = m_tunnel_encap_nexthop_map.find(object_id);
                if (encap_map_it == m_tunnel_encap_nexthop_map.end()) {
                    SWSS_LOG_ERROR("Failed to find sw_if_index for %s",
                        tunnel_nh_obj->get_id().c_str());
                    continue;
                }
                remove_vpp_vxlan_decap(encap_map_it->second);
                remove_vpp_vxlan_encap(req, encap_map_it->second);

                m_tunnel_encap_nexthop_map.erase(encap_map_it);
            }
        }
    }
    return SAI_STATUS_SUCCESS;
}
sai_status_t
TunnelManager::create_tunnel_encap_nexthop(
                    _In_ const std::string& serializedObjectId,
                    _In_ sai_object_id_t switch_id,
                    _In_ uint32_t attr_count,
                    _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    SaiCachedObject tunnel_nh_obj(m_switch_db, SAI_OBJECT_TYPE_NEXT_HOP, serializedObjectId, attr_count, attr_list);
    return tunnel_encap_nexthop_action(&tunnel_nh_obj, Action::CREATE);
}

sai_status_t
TunnelManager::remove_tunnel_encap_nexthop(
                _In_ const std::string& serializedObjectId)
{
    SWSS_LOG_ENTER();

    auto tunnel_nh_obj = m_switch_db->get_sai_object(SAI_OBJECT_TYPE_NEXT_HOP, serializedObjectId);

    if (!tunnel_nh_obj) {
        SWSS_LOG_ERROR("Failed to find SAI_OBJECT_TYPE_NEXT_HOP SaiObject: %s", serializedObjectId.c_str());
        return SAI_STATUS_FAILURE;
    }
    return tunnel_encap_nexthop_action(tunnel_nh_obj.get(), Action::DELETE);
}

std::pair<bool, uint32_t>
TunnelManager::find_existing_vxlan_tunnel(
                    _In_ const vpp_vxlan_tunnel_t& req)
{
    SWSS_LOG_ENTER();

    /* Convert req IPs to sai_ip_address_t for comparison with L3TunnelVPPData */
    sai_ip_address_t req_src, req_dst;
    memset(&req_src, 0, sizeof(req_src));
    memset(&req_dst, 0, sizeof(req_dst));

    if (req.src_address.sa_family == AF_INET)
    {
        req_src.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        memcpy(&req_src.addr.ip4, &req.src_address.addr.ip4.sin_addr, 4);
        req_dst.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        memcpy(&req_dst.addr.ip4, &req.dst_address.addr.ip4.sin_addr, 4);
    }
    else
    {
        req_src.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&req_src.addr.ip6, &req.src_address.addr.ip6.sin6_addr, 16);
        req_dst.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(&req_dst.addr.ip6, &req.dst_address.addr.ip6.sin6_addr, 16);
    }

    for (const auto& pair : m_l3_tunnel_map)
    {
        const auto& data = pair.second;
        if (data.vni != req.vni)
            continue;
        if (data.src_ip.addr_family != req_src.addr_family)
            continue;

        bool src_match, dst_match;
        if (req_src.addr_family == SAI_IP_ADDR_FAMILY_IPV4)
        {
            src_match = (memcmp(&req_src.addr.ip4, &data.src_ip.addr.ip4, 4) == 0);
            dst_match = (memcmp(&req_dst.addr.ip4, &data.dst_ip.addr.ip4, 4) == 0);
        }
        else
        {
            src_match = (memcmp(&req_src.addr.ip6, &data.src_ip.addr.ip6, 16) == 0);
            dst_match = (memcmp(&req_dst.addr.ip6, &data.dst_ip.addr.ip6, 16) == 0);
        }

        if (src_match && dst_match)
        {
            SWSS_LOG_NOTICE("find_existing_vxlan_tunnel: found L3 tunnel vni=%d sw_if_index=%d",
                    data.vni, data.sw_if_index);
            return {true, data.sw_if_index};
        }
    }

    return {false, 0};
}

sai_status_t
TunnelManager::create_vpp_vxlan_encap(
                    _In_  vpp_vxlan_tunnel_t& req,
                    _Out_ TunnelVPPData& tunnel_data)
{
    SWSS_LOG_ENTER();

    int                         vpp_status;
    u_int32_t                   sw_if_index;
    char                        src_ip_str[INET6_ADDRSTRLEN];
    char                        dst_ip_str[INET6_ADDRSTRLEN];
    auto                        router_mac = get_router_mac();
    auto                        bvi_mac = router_mac.data();

    vpp_status = vpp_vxlan_tunnel_add_del(&req, 1, &sw_if_index);
    vpp_ip_addr_t_to_string(&req.src_address, src_ip_str, INET6_ADDRSTRLEN);
    vpp_ip_addr_t_to_string(&req.dst_address, dst_ip_str, INET6_ADDRSTRLEN);
    SWSS_LOG_INFO("create vxlan tunnel src %s dst %s vni %d: sw_if_index,%d, status %d",
            src_ip_str, dst_ip_str,
            req.vni, sw_if_index, vpp_status);

    // If creation returned sw_if_index 0, the tunnel may already exist from a
    // previous boot (docker commit persists VPP state).  Delete and re-create
    // to get the correct sw_if_index.
    if (vpp_status == 0 && sw_if_index == 0) {
        SWSS_LOG_NOTICE("VxLAN tunnel add returned sw_if_index=0, deleting stale tunnel and retrying");
        u_int32_t dummy_idx = 0;
        vpp_vxlan_tunnel_add_del(&req, 0, &dummy_idx);  // delete
        vpp_status = vpp_vxlan_tunnel_add_del(&req, 1, &sw_if_index);  // re-create
        SWSS_LOG_NOTICE("VxLAN tunnel re-create: sw_if_index=%d, status=%d",
                sw_if_index, vpp_status);
    }

    if (vpp_status != 0) {
        // Tunnel may already exist (e.g., L3 VxLAN tunnel created at boot by
        // vpp_l3_vxlan_tunnel_add).  Look up existing tunnel by src/dst/VNI
        // and reuse its sw_if_index instead of failing.
        auto existing = find_existing_vxlan_tunnel(req);
        if (existing.first) {
            sw_if_index = existing.second;
            SWSS_LOG_NOTICE("VxLAN tunnel already exists (src %s dst %s vni %d), reusing sw_if_index %d",
                    src_ip_str, dst_ip_str, req.vni, sw_if_index);
        } else {
            SWSS_LOG_ERROR("Failed to create vxlan tunnel");
            return SAI_STATUS_FAILURE;
        }
    }
    tunnel_data.sw_if_index = sw_if_index;
    /* the neighbour is to build inner ether. use no_fib_entry to avoid creating the nh in the fib, which will mess up underlay forwarding*/
    if (req.dst_address.sa_family == AF_INET6) {
        ip6_nbr_add_del(NULL, sw_if_index, &req.dst_address.addr.ip6, false, true/*no_fib_entry*/, bvi_mac, 1);
    } else {
        ip4_nbr_add_del(NULL, sw_if_index, &req.dst_address.addr.ip4, false, true/*no_fib_entry*/, bvi_mac, 1);
    }
    SWSS_LOG_INFO("successfully created encap for vxlan tunnel %d", sw_if_index);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
TunnelManager::remove_vpp_vxlan_encap(
                    _In_  vpp_vxlan_tunnel_t& req,
                    _In_ TunnelVPPData& tunnel_data)
{
    SWSS_LOG_ENTER();

    int                         vpp_status;
    u_int32_t                   sw_if_index = tunnel_data.sw_if_index;
    char                        src_ip_str[INET6_ADDRSTRLEN];
    char                        dst_ip_str[INET6_ADDRSTRLEN];
    auto                        router_mac = get_router_mac();
    auto                        bvi_mac = router_mac.data();

    if (req.dst_address.sa_family == AF_INET6) {
        ip6_nbr_add_del(NULL, tunnel_data.sw_if_index, &req.dst_address.addr.ip6, false, true/*no_fib_entry*/, bvi_mac, 0);
    } else {
        ip4_nbr_add_del(NULL, tunnel_data.sw_if_index, &req.dst_address.addr.ip4, false, true/*no_fib_entry*/, bvi_mac, 0);
    }

    /* Don't delete the VxLAN tunnel if it's a shared L3 tunnel created at
     * boot — it's managed by vpp_l3_vxlan_tunnel_add/remove lifecycle,
     * not by per-nexthop lifecycle. */
    auto existing = find_existing_vxlan_tunnel(req);
    if (existing.first && existing.second == tunnel_data.sw_if_index) {
        SWSS_LOG_NOTICE("Skipping VxLAN tunnel delete — shared L3 tunnel sw_if_index %d",
                tunnel_data.sw_if_index);
        return SAI_STATUS_SUCCESS;
    }

    vpp_status = vpp_vxlan_tunnel_add_del(&req, 0, &sw_if_index);
    vpp_ip_addr_t_to_string(&req.src_address, src_ip_str, INET6_ADDRSTRLEN);
    vpp_ip_addr_t_to_string(&req.dst_address, dst_ip_str, INET6_ADDRSTRLEN);
    SWSS_LOG_INFO("delete vxlan tunnel src %s dst %s vni %d: sw_if_index %d, status %d",
            src_ip_str, dst_ip_str,
            req.vni, sw_if_index, vpp_status);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to delete vxlan tunnel");
        return SAI_STATUS_FAILURE;
    }
    return SAI_STATUS_SUCCESS;
}
sai_status_t
TunnelManager::create_vpp_vxlan_decap(
                    _Out_ TunnelVPPData& tunnel_data)
{
    SWSS_LOG_ENTER();

    int                         vpp_status;
    char                        hw_bvi_ifname[32];
    auto                        router_mac = get_router_mac();
    auto                        bvi_mac = router_mac.data();
    vpp_ip_route_t              bvi_ip_prefix;
    uint32_t                    tunnel_if_index = tunnel_data.sw_if_index;

    //allocate bridge domain ID
    int bd_id = m_switch_db->dynamic_bd_id_pool.alloc();
    if (bd_id == -1) {
        SWSS_LOG_ERROR("Failed to allocate bridge domain ID");
        return SAI_STATUS_FAILURE;
    }
    tunnel_data.bd_id = bd_id;
    //create bvi interface using instance same as bd_id
    vpp_status = create_bvi_interface(bvi_mac, bd_id);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to create bvi interface");
        m_switch_db->dynamic_bd_id_pool.free(bd_id);
        return SAI_STATUS_FAILURE;
    }
    // Get new list of physical interfaces from VS
    refresh_interfaces_list();

    //bring up bvi interface
    snprintf(hw_bvi_ifname, sizeof(hw_bvi_ifname), "bvi%u", bd_id);
    vpp_status = interface_set_state(hw_bvi_ifname, true);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to bring up bvi interface");
        return SAI_STATUS_FAILURE;
    }

    //Create bridge and set BVI to the BD
    vpp_status = set_sw_interface_l2_bridge(hw_bvi_ifname, bd_id, true, VPP_API_PORT_TYPE_BVI);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to add bvi interface to bd");
        return SAI_STATUS_FAILURE;
    }

    //bind bvi to vrf
    vpp_status = set_interface_vrf(hw_bvi_ifname, 0, tunnel_data.ip_vrf->m_vrf_id, tunnel_data.ip_vrf->m_is_ipv6);

    //set bvi IPv4
    uint16_t offset = (uint16_t)((uint16_t)(bd_id - SwitchVpp::dynamic_bd_id_base) + 2);

    bvi_ip_prefix.prefix_len = 32;
    bvi_ip_prefix.prefix_addr.sa_family = AF_INET;
    struct sockaddr_in *sin =  &bvi_ip_prefix.prefix_addr.addr.ip4;
    sin->sin_addr.s_addr = htonl(offset);
    vpp_status = interface_ip_address_add_del(hw_bvi_ifname, &bvi_ip_prefix, true);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to config IP on bvi interface");
        return SAI_STATUS_FAILURE;
    }

    //set bvi IPv6 (the same tunnel can carry ipv4 or ipv6)
    bvi_ip_prefix.prefix_len = 128;
    bvi_ip_prefix.prefix_addr.sa_family = AF_INET6;
    struct sockaddr_in6 *sin6 =  &bvi_ip_prefix.prefix_addr.addr.ip6;
    memset(&sin6->sin6_addr, 0, sizeof(struct in6_addr));
    sin6->sin6_addr.s6_addr[14] = (uint8_t)(offset >> 8) & 0xFF;
    sin6->sin6_addr.s6_addr[15] = (uint8_t)(offset & 0xFF);
    vpp_status = interface_ip_address_add_del(hw_bvi_ifname, &bvi_ip_prefix, true);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to config IP on bvi interface");
        return SAI_STATUS_FAILURE;
    }

    //set vxlan tunnel to bridge domain
    vpp_status = set_sw_interface_l2_bridge_by_index(tunnel_if_index, bd_id, true, VPP_API_PORT_TYPE_NORMAL);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to add tunnel interface to bd");
        return SAI_STATUS_FAILURE;
    }
    SWSS_LOG_INFO("successfully created decap for vxlan tunnel %d with BD %d",
                        tunnel_if_index, bd_id);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
TunnelManager::remove_vpp_vxlan_decap(
                    _In_ TunnelVPPData& tunnel_data)
{
    SWSS_LOG_ENTER();

    char                        hw_bvi_ifname[32];

    snprintf(hw_bvi_ifname, sizeof(hw_bvi_ifname), "bvi%u", tunnel_data.bd_id);

    delete_bvi_interface(hw_bvi_ifname);

    m_switch_db->dynamic_bd_id_pool.free(tunnel_data.bd_id);
    refresh_interfaces_list();
    //bd is create automatically when the fist interface is add to it but requires manual deletion
    vpp_bridge_domain_add_del(tunnel_data.bd_id, false);
    SWSS_LOG_INFO("successfully deleted decap of vxlan tunnel %d with BD %d",
                        tunnel_data.sw_if_index, tunnel_data.bd_id);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
TunnelManager::create_l2_vxlan_tunnel(
    _In_ sai_object_id_t tunnel_oid,
    _Out_ uint32_t& sw_if_index)
{
    SWSS_LOG_ENTER();

    sw_if_index = ~0;

    // Check if already created
    auto it = m_l2_tunnel_map.find(tunnel_oid);
    if (it != m_l2_tunnel_map.end()) {
        sw_if_index = it->second.sw_if_index;
        SWSS_LOG_NOTICE("L2 VXLAN tunnel already exists: tunnel=%s sw_if=%u",
            sai_serialize_object_id(tunnel_oid).c_str(), sw_if_index);
        return SAI_STATUS_SUCCESS;
    }

    // Get tunnel object
    auto tunnel_obj = m_switch_db->get_sai_object(SAI_OBJECT_TYPE_TUNNEL,
        sai_serialize_object_id(tunnel_oid));
    if (!tunnel_obj) {
        SWSS_LOG_ERROR("Tunnel %s not found", sai_serialize_object_id(tunnel_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    // Check tunnel type
    sai_attribute_t attr;
    attr.id = SAI_TUNNEL_ATTR_TYPE;
    if (tunnel_obj->get_attr(attr) != SAI_STATUS_SUCCESS) {
        SWSS_LOG_ERROR("Missing SAI_TUNNEL_ATTR_TYPE");
        return SAI_STATUS_FAILURE;
    }
    if (attr.value.s32 != SAI_TUNNEL_TYPE_VXLAN) {
        SWSS_LOG_NOTICE("Not a VXLAN tunnel (type=%d), skipping", attr.value.s32);
        return SAI_STATUS_SUCCESS;
    }

    // Get src IP
    attr.id = SAI_TUNNEL_ATTR_ENCAP_SRC_IP;
    if (tunnel_obj->get_attr(attr) != SAI_STATUS_SUCCESS) {
        SWSS_LOG_ERROR("Missing ENCAP_SRC_IP");
        return SAI_STATUS_FAILURE;
    }
    sai_ip_address_t src_ip = attr.value.ipaddr;

    // Get dst IP - if missing, this is local VTEP, not P2P tunnel
    attr.id = SAI_TUNNEL_ATTR_ENCAP_DST_IP;
    if (tunnel_obj->get_attr(attr) != SAI_STATUS_SUCCESS) {
        SWSS_LOG_NOTICE("No ENCAP_DST_IP - local VTEP tunnel, skipping VPP creation");
        return SAI_STATUS_SUCCESS;
    }
    sai_ip_address_t dst_ip = attr.value.ipaddr;

    // Find VNI and VLAN from decap mappers
    uint32_t vni = 0;
    uint16_t vlan_id = 0;

    auto decap_mappers = tunnel_obj->get_linked_objects(
        SAI_OBJECT_TYPE_TUNNEL_MAP, SAI_TUNNEL_ATTR_DECAP_MAPPERS);
    
    SWSS_LOG_NOTICE("Found %zu decap mappers", decap_mappers.size());

    for (auto mapper : decap_mappers) {
        attr.id = SAI_TUNNEL_MAP_ATTR_TYPE;
        if (mapper->get_attr(attr) != SAI_STATUS_SUCCESS) continue;
        SWSS_LOG_NOTICE("Mapper type: %d", attr.value.s32);
        if (attr.value.s32 != SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID) continue;

        auto entries = mapper->get_child_objs(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY);
        if (!entries) {
            SWSS_LOG_NOTICE("No entries in mapper");
            continue;
        }

        SWSS_LOG_NOTICE("Mapper has %zu entries", entries->size());

        for (auto& entry_pair : *entries) {
            auto entry = entry_pair.second;

            // Get VNI
            attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY;
            if (entry->get_attr(attr) == SAI_STATUS_SUCCESS) {
                vni = attr.value.u32;
                SWSS_LOG_NOTICE("Found VNI=%u", vni);
            }

            // Get VLAN ID
            attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE;
            if (entry->get_attr(attr) == SAI_STATUS_SUCCESS) {
                vlan_id = attr.value.u16;
                SWSS_LOG_NOTICE("Found VLAN=%u", vlan_id);
            }

            if (vni != 0 && vlan_id != 0) break;
        }
        if (vni != 0 && vlan_id != 0) break;
    }

    if (vni == 0) {
        SWSS_LOG_ERROR("No VNI found in tunnel mappers for tunnel %s",
            sai_serialize_object_id(tunnel_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    if (vlan_id == 0) {
        SWSS_LOG_ERROR("No VLAN found in tunnel mappers for tunnel %s",
            sai_serialize_object_id(tunnel_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    // Create VPP tunnel
    vpp_vxlan_tunnel_t req;
    memset(&req, 0, sizeof(req));
    req.vni = vni;
    req.src_port = m_vxlan_port;
    req.dst_port = m_vxlan_port;
    req.instance = ~0;
    req.decap_next_index = ~0;
    sai_ip_address_t_to_vpp_ip_addr_t(src_ip, req.src_address);
    sai_ip_address_t_to_vpp_ip_addr_t(dst_ip, req.dst_address);

    TunnelVPPData tunnel_data;
    tunnel_data.vni = vni;
    tunnel_data.src_ip = src_ip;
    tunnel_data.dst_ip = dst_ip;
    tunnel_data.vlan_id = vlan_id;  // Store for cleanup

    std::string default_vrf = "default";
    tunnel_data.ip_vrf = std::make_shared<IpVrfInfo>(SAI_NULL_OBJECT_ID, 0, default_vrf, false);

    if (create_vpp_vxlan_encap(req, tunnel_data) != SAI_STATUS_SUCCESS) {
        SWSS_LOG_ERROR("Failed to create VPP VXLAN tunnel");
        return SAI_STATUS_FAILURE;
    }

    // Guard against sw_if_index=0 — VPP's local0 loopback.  If the VxLAN
    // encap creation returned 0, it silently failed (e.g. BGP hasn't resolved
    // the remote VTEP yet).  Adding local0 to a BD corrupts forwarding.
    if (tunnel_data.sw_if_index == 0) {
        SWSS_LOG_ERROR("VxLAN tunnel creation returned sw_if_index=0 (local0), aborting BD add");
        return SAI_STATUS_FAILURE;
    }

    // Add tunnel interface to bridge domain (VLAN) with SHG=1
    // SHG (Split Horizon Group) isolation: local ports use SHG=0, tunnel uses SHG=1.
    // This prevents BUM traffic from flooding local→tunnel during steady state.
    // Known unicast forwarding via static L2FIB entries bypasses SHG, so failover
    // reroute (MAC → tunnel) works without removing the SHG barrier.
    // This models the future ASIC protection-group behavior where the tunnel is
    // pre-provisioned as a backup path but inactive for BUM until failover.
    if (vlan_id != 0) {
        const uint32_t tunnel_shg = 1;
        int vpp_status = set_sw_interface_l2_bridge_by_index_with_shg(
            tunnel_data.sw_if_index, vlan_id, true, VPP_API_PORT_TYPE_NORMAL, tunnel_shg);
        if (vpp_status != 0) {
            SWSS_LOG_ERROR("Failed to add tunnel sw_if %u to BD %u",
                tunnel_data.sw_if_index, vlan_id);
            // Cleanup the tunnel
            remove_vpp_vxlan_encap(req, tunnel_data);
            return SAI_STATUS_FAILURE;
        }
        SWSS_LOG_NOTICE("Added tunnel sw_if %u to BD %u with SHG=%u",
            tunnel_data.sw_if_index, vlan_id, tunnel_shg);

        // NOTE: Do NOT call set_l2_interface_flags() to disable learning on the
        // tunnel port. VPP's l2_flags API corrupts the per-interface l2-output
        // feature config, causing SIGSEGV in l2output_node_fn_icl when the first
        // BUM packet floods through the tunnel. (VPP v2510 bug.)
        //
        // Tunnel learning is harmless in EVPN MH:
        // - Remote MACs learned on tunnel are correct (reachable via peer VTEP)
        // - Local MACs always win on local ports (more frequent traffic)
        // - SHG=1 prevents tunnel→tunnel BUM loops
        // - Our event handler already skips tunnel-learned MACs for SAI FDB events
    }

    m_l2_tunnel_map[tunnel_oid] = tunnel_data;
    sw_if_index = tunnel_data.sw_if_index;

    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    vpp_ip_addr_t_to_string(&req.src_address, src_str, sizeof(src_str));
    vpp_ip_addr_t_to_string(&req.dst_address, dst_str, sizeof(dst_str));

    SWSS_LOG_NOTICE("Created L2 VXLAN: tunnel=%s src=%s dst=%s VNI=%u VLAN=%u sw_if=%u",
        sai_serialize_object_id(tunnel_oid).c_str(), src_str, dst_str, vni, vlan_id, sw_if_index);

    /*
     * Place any L3 VxLAN tunnel with the same src/dst VTEP pair into this
     * overlay BD (with SHG=1).
     *
     * L3 tunnels are created VRF-bound for encap, but VPP's VxLAN decap
     * defaults to l2-input.  Without explicit BD placement the L3 tunnel
     * ends up in an auto-assigned BD (e.g. 4096) and decapped packets
     * can't reach the overlay BVI — causing "BVI L3 mac mismatch" drops.
     *
     * Placing the L3 tunnel in the same BD as the L2 tunnel allows
     * decapped failover traffic to reach bvi<N> for L3 routing to the
     * local server.  SHG=1 prevents BUM flooding issues.
     *
     * Note: learning is NOT disabled (VPP l2_flags API bug causes SIGSEGV).
     * SHG=1 is sufficient — BUM doesn't cross between tunnel ports, and
     * L3 tunnel traffic is rare (only during failover).
     */
    if (vlan_id != 0)
    {
        for (auto& l3_pair : m_l3_tunnel_map)
        {
            auto& l3_data = l3_pair.second;

            /* Match by src/dst VTEP IPs (L3 and L2 tunnels share the same
             * VTEP pair but use different VNIs) */
            bool src_match = false, dst_match = false;

            if (src_ip.addr_family == l3_data.src_ip.addr_family)
            {
                if (src_ip.addr_family == SAI_IP_ADDR_FAMILY_IPV4)
                {
                    src_match = (memcmp(&src_ip.addr.ip4,
                                        &l3_data.src_ip.addr.ip4, 4) == 0);
                    dst_match = (memcmp(&dst_ip.addr.ip4,
                                        &l3_data.dst_ip.addr.ip4, 4) == 0);
                }
                else
                {
                    src_match = (memcmp(&src_ip.addr.ip6,
                                        &l3_data.src_ip.addr.ip6, 16) == 0);
                    dst_match = (memcmp(&dst_ip.addr.ip6,
                                        &l3_data.dst_ip.addr.ip6, 16) == 0);
                }
            }

            if (src_match && dst_match)
            {
                const uint32_t l3_shg = 1;
                int l3_status = set_sw_interface_l2_bridge_by_index_with_shg(
                    l3_data.sw_if_index, vlan_id, true,
                    VPP_API_PORT_TYPE_NORMAL, l3_shg);

                if (l3_status == 0)
                {
                    SWSS_LOG_NOTICE("Placed L3 tunnel sw_if %u (VNI=%u) "
                                    "into BD %u with SHG=%u for decap path",
                                    l3_data.sw_if_index, l3_data.vni,
                                    vlan_id, l3_shg);
                }
                else
                {
                    SWSS_LOG_ERROR("Failed to place L3 tunnel sw_if %u "
                                   "into BD %u (status=%d)",
                                   l3_data.sw_if_index, vlan_id, l3_status);
                }
                /* Only one L3 tunnel per src/dst pair */
                break;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
TunnelManager::remove_l2_vxlan_tunnel(
    _In_ sai_object_id_t tunnel_oid)
{
    SWSS_LOG_ENTER();

    auto it = m_l2_tunnel_map.find(tunnel_oid);
    if (it == m_l2_tunnel_map.end()) {
        // Not an L2 tunnel we manage, could be L3 or P2MP, skip silently
        SWSS_LOG_NOTICE("Tunnel %s not in L2 tunnel map, skipping removal",
            sai_serialize_object_id(tunnel_oid).c_str());
        return SAI_STATUS_SUCCESS;
    }

    TunnelVPPData& tunnel_data = it->second;

    // Remove tunnel interface from bridge domain
    int vpp_status = set_sw_interface_l2_bridge_by_index(
        tunnel_data.sw_if_index, tunnel_data.vlan_id,
        false,  // false = remove from BD
        VPP_API_PORT_TYPE_NORMAL);
    if (vpp_status != 0) {
        SWSS_LOG_ERROR("Failed to remove tunnel sw_if %u from BD %u",
            tunnel_data.sw_if_index, tunnel_data.vlan_id);
        // Continue with tunnel deletion anyway
    } else {
        SWSS_LOG_NOTICE("Removed tunnel sw_if %u from BD %u",
            tunnel_data.sw_if_index, tunnel_data.vlan_id);
    }
    
    // Delete the VPP VXLAN tunnel interface
    // Reconstruct the request needed by remove_vpp_vxlan_encap
    vpp_vxlan_tunnel_t req;
    memset(&req, 0, sizeof(req));
    req.vni = tunnel_data.vni;
    req.src_port = m_vxlan_port;
    req.dst_port = m_vxlan_port;
    req.instance = ~0;
    req.decap_next_index = ~0;
    sai_ip_address_t_to_vpp_ip_addr_t(tunnel_data.src_ip, req.src_address);
    sai_ip_address_t_to_vpp_ip_addr_t(tunnel_data.dst_ip, req.dst_address);

    sai_status_t status = remove_vpp_vxlan_encap(req, tunnel_data);
    if (status != SAI_STATUS_SUCCESS) {
        SWSS_LOG_ERROR("Failed to remove VPP VXLAN tunnel for %s",
            sai_serialize_object_id(tunnel_oid).c_str());
        // Still remove from map to avoid stale entries
    }

    SWSS_LOG_NOTICE("Removed L2 VXLAN tunnel %s (sw_if=%u, VNI=%u, VLAN=%u)",
        sai_serialize_object_id(tunnel_oid).c_str(),
        tunnel_data.sw_if_index, tunnel_data.vni, tunnel_data.vlan_id);

    // Remove from map
    m_l2_tunnel_map.erase(it);

    return SAI_STATUS_SUCCESS;
}

// ─── L3 VxLAN Tunnel (VRF-bound) ──────────────────────────────────────────────

sai_status_t
TunnelManager::create_l3_vxlan_tunnel(
    _In_ sai_object_id_t tunnel_oid,
    _In_ uint32_t vni,
    _In_ uint32_t vrf_id,
    _In_ const sai_ip_address_t &src,
    _In_ const sai_ip_address_t &dst)
{
    SWSS_LOG_ENTER();

    // Check if already created
    auto it = m_l3_tunnel_map.find(tunnel_oid);
    if (it != m_l3_tunnel_map.end()) {
        SWSS_LOG_NOTICE("L3 VxLAN tunnel already exists: tunnel=%s sw_if=%u",
            sai_serialize_object_id(tunnel_oid).c_str(), it->second.sw_if_index);
        return SAI_STATUS_SUCCESS;
    }

    // Only IPv4 src/dst supported for now
    if (src.addr_family != SAI_IP_ADDR_FAMILY_IPV4 ||
        dst.addr_family != SAI_IP_ADDR_FAMILY_IPV4) {
        SWSS_LOG_ERROR("L3 VxLAN tunnel: only IPv4 VTEP addresses supported");
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    uint32_t sw_if_index = 0;
    int ret = vpp_l3_vxlan_tunnel_add(
        src.addr.ip4, dst.addr.ip4, vni, vrf_id, &sw_if_index);

    if (ret != 0) {
        /*
         * Tunnel may already exist in VPP from a previous boot cycle
         * (syncd restart doesn't destroy VPP tunnels).  Query VPP
         * directly via vppctl to find the existing tunnel's sw_if_index.
         *
         * We can't use find_existing_vxlan_tunnel() here because
         * m_l3_tunnel_map is empty after syncd restart — the tunnel
         * exists in VPP but not in our in-memory map.
         */
        char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.addr.ip4, src_str, sizeof(src_str));
        inet_ntop(AF_INET, &dst.addr.ip4, dst_str, sizeof(dst_str));

        /* Parse `vppctl show vxlan tunnel` output to find matching tunnel */
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "vppctl show vxlan tunnel 2>/dev/null | "
                 "grep 'src %s dst %s.*vni %u' | "
                 "head -1 | sed 's/.*sw-if-idx //' | awk '{print $1}'",
                 src_str, dst_str, vni);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char buf[32];
            if (fgets(buf, sizeof(buf), fp)) {
                sw_if_index = (uint32_t)atoi(buf);
            }
            pclose(fp);
        }

        if (sw_if_index > 0) {
            SWSS_LOG_NOTICE("L3 VxLAN tunnel already exists in VPP: "
                            "VNI=%u VRF=%u sw_if=%u src=%s dst=%s (reusing)",
                            vni, vrf_id, sw_if_index, src_str, dst_str);
            /* VRF binding persists from previous boot — no need to re-bind */
        } else {
            SWSS_LOG_ERROR("Failed to create L3 VxLAN tunnel: VNI=%u VRF=%u "
                           "ret=%d (and no existing tunnel found in VPP)",
                           vni, vrf_id, ret);
            return SAI_STATUS_FAILURE;
        }
    }

    if (sw_if_index == 0) {
        SWSS_LOG_ERROR("L3 VxLAN tunnel returned sw_if_index=0 (local0)");
        return SAI_STATUS_FAILURE;
    }

    // Add static neighbor for inner Ethernet header (same pattern as L2)
    auto router_mac = get_router_mac();
    auto bvi_mac = router_mac.data();
    vpp_ip_addr_t dst_vpp;
    sai_ip_address_t dst_copy = dst;
    sai_ip_address_t_to_vpp_ip_addr_t(dst_copy, dst_vpp);
    ip4_nbr_add_del(NULL, sw_if_index, &dst_vpp.addr.ip4,
                     false, true/*no_fib_entry*/, bvi_mac, 1);

    L3TunnelVPPData data;
    data.sw_if_index = sw_if_index;
    data.vni = vni;
    data.vrf_id = vrf_id;
    data.src_ip = src;
    data.dst_ip = dst;
    data.tunnel_oid = tunnel_oid;

    m_l3_tunnel_map[tunnel_oid] = data;

    SWSS_LOG_NOTICE("Created L3 VxLAN: tunnel=%s VNI=%u VRF=%u sw_if=%u",
        sai_serialize_object_id(tunnel_oid).c_str(), vni, vrf_id, sw_if_index);

    /*
     * Add a default deag (re-lookup) route in the overlay VRF so that
     * VxLAN tunnel encap can resolve remote VTEP IPs through the underlay.
     *
     * Without this, the overlay VRF (table 1001) has no route to the
     * remote VTEP loopback IPs, and VPP drops encapsulated packets.
     * The deag route causes VPP to re-lookup in the underlay table (0)
     * where BGP-learned routes to remote VTEPs exist.
     *
     * Skip for VRF 0 (underlay itself) to avoid recursive loops.
     */
    if (vrf_id != 0)
    {
        char deag_cmd[128];
        snprintf(deag_cmd, sizeof(deag_cmd),
                 "vppctl ip route add 0.0.0.0/0 table %u via ip4-lookup-in-table 0",
                 vrf_id);
        int deag_ret = system(deag_cmd);
        if (deag_ret == 0)
        {
            SWSS_LOG_NOTICE("L3 VxLAN: added default deag route in VRF %u → table 0",
                            vrf_id);
        }
        else
        {
            SWSS_LOG_WARN("L3 VxLAN: failed to add deag route in VRF %u (ret=%d)",
                          vrf_id, deag_ret);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
TunnelManager::remove_l3_vxlan_tunnel(
    _In_ sai_object_id_t tunnel_oid)
{
    SWSS_LOG_ENTER();

    auto it = m_l3_tunnel_map.find(tunnel_oid);
    if (it == m_l3_tunnel_map.end()) {
        SWSS_LOG_NOTICE("Tunnel %s not in L3 tunnel map, skipping removal",
            sai_serialize_object_id(tunnel_oid).c_str());
        return SAI_STATUS_SUCCESS;
    }

    L3TunnelVPPData& data = it->second;

    // Remove static neighbor
    auto router_mac = get_router_mac();
    auto bvi_mac = router_mac.data();
    vpp_ip_addr_t dst_vpp;
    sai_ip_address_t_to_vpp_ip_addr_t(data.dst_ip, dst_vpp);
    ip4_nbr_add_del(NULL, data.sw_if_index, &dst_vpp.addr.ip4,
                     false, true/*no_fib_entry*/, bvi_mac, 0);

    int ret = vpp_l3_vxlan_tunnel_del(
        data.sw_if_index, data.src_ip.addr.ip4, data.dst_ip.addr.ip4, data.vni);
    if (ret != 0) {
        SWSS_LOG_ERROR("Failed to delete L3 VxLAN tunnel sw_if=%u: ret=%d",
            data.sw_if_index, ret);
    }

    SWSS_LOG_NOTICE("Removed L3 VxLAN tunnel %s (sw_if=%u, VNI=%u, VRF=%u)",
        sai_serialize_object_id(tunnel_oid).c_str(),
        data.sw_if_index, data.vni, data.vrf_id);

    m_l3_tunnel_map.erase(it);

    return SAI_STATUS_SUCCESS;
}
