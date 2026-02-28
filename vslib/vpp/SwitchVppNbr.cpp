#include "SwitchVpp.h"

#include "meta/sai_serialize.h"
#include "meta/NotificationPortStateChange.h"

#include "swss/logger.h"
#include "swss/exec.h"
#include "swss/converter.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vppxlate/SaiVppXlate.h"

using namespace saivs;

sai_status_t SwitchVpp::addRemoveIpNbr(
        _In_ const std::string &serializedObjectId,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list,
        _In_ bool is_add)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;
    sai_neighbor_entry_t nbr_entry;

    sai_deserialize_neighbor_entry(serializedObjectId, nbr_entry);

    /* Check SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE — when true, suppress
     * the automatic /32 host route in VPP (pass no_fib_entry=true to
     * ip4/ip6_nbr_add_del).  Used by EVPN MH HW FRR so the explicit
     * PROTECTION NHG route owns the /32 exclusively. */
    bool no_host_route = false;
    for (uint32_t i = 0; i < attr_count; i++)
    {
        if (attr_list[i].id == SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE)
        {
            no_host_route = attr_list[i].value.booldata;
            if (no_host_route)
            {
                SWSS_LOG_NOTICE("Neighbor %s: NO_HOST_ROUTE=true, suppressing /32 FIB entry",
                                serializedObjectId.c_str());
            }
            break;
        }
    }

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;

    CHECK_STATUS(get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, nbr_entry.rif_id, 1, &attr));

    int32_t rif_type = attr.value.s32;

    /*
     * For VLAN-type RIF (BVI), program the bridge domain ARP termination
     * table via bd_ip_mac_add_del so that VPP can respond to ARP requests
     * on behalf of hosts in the bridge domain (proxy ARP / ARP termination).
     *
     * On a real ASIC, ARP termination entries persist in hardware until
     * explicitly cleared by the control plane.  In the VPP data path the
     * Vlan SVI has no IPv4 address (it lives on the BVI tap instead), so
     * the kernel neighbor for static NEIGH entries transitions to FAILED
     * and neighsyncd issues a SAI remove.  Honoring that remove would
     * leave the bridge domain without proxy-ARP coverage, breaking
     * overlay connectivity.
     *
     * To match real ASIC behavior we only program arp-term on *add* and
     * silently accept (but ignore) the remove — the entry stays in VPP's
     * BD ip-mac table until the BD itself is destroyed.
     */
    if (rif_type == SAI_ROUTER_INTERFACE_TYPE_VLAN)
    {
        if (!is_add)
        {
            SWSS_LOG_NOTICE("Keeping BD ARP term entry for neighbor %s "
                            "(ignoring remove to match ASIC behavior)",
                            serializedObjectId.c_str());
            return SAI_STATUS_SUCCESS;
        }

        attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
        CHECK_STATUS(get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, nbr_entry.rif_id, 1, &attr));

        sai_object_id_t vlan_oid = attr.value.oid;

        attr.id = SAI_VLAN_ATTR_VLAN_ID;
        CHECK_STATUS(get(SAI_OBJECT_TYPE_VLAN, vlan_oid, 1, &attr));

        uint32_t bd_id = (uint32_t)attr.value.u16;

        /*
         * SAI proxy ARP behavior: the switch responds to ARP requests with
         * its own SVI MAC, not the target host's real MAC.  This forces all
         * traffic through the switch's L3 forwarding path, matching real
         * ASIC behavior per the SONiC Proxy ARP HLD.
         *
         * Read the BVI's MAC (anycast gateway MAC) from the RIF's
         * SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS attribute.  If not
         * available, fall back to the neighbor's MAC (pre-existing behavior).
         */
        sai_mac_t nbr_mac;
        sai_mac_t svi_mac;
        bool use_svi_mac = false;
        bool no_mac = true;

        /* Try to get the RIF's SRC_MAC (BVI/anycast gateway MAC) */
        sai_attribute_t rif_mac_attr;
        rif_mac_attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
        if (get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, nbr_entry.rif_id, 1, &rif_mac_attr) == SAI_STATUS_SUCCESS)
        {
            memcpy(svi_mac, rif_mac_attr.value.mac, sizeof(sai_mac_t));
            /* Verify it's not all zeros */
            bool all_zero = true;
            for (int i = 0; i < 6; i++) {
                if (svi_mac[i] != 0) { all_zero = false; break; }
            }
            if (!all_zero)
            {
                use_svi_mac = true;
                SWSS_LOG_NOTICE("BD %d ARP term: using SVI MAC %02x:%02x:%02x:%02x:%02x:%02x "
                                "(proxy ARP) for neighbor %s",
                                bd_id,
                                svi_mac[0], svi_mac[1], svi_mac[2],
                                svi_mac[3], svi_mac[4], svi_mac[5],
                                serializedObjectId.c_str());
            }
        }

        /* Get the neighbor's real MAC (used as fallback) */
        for (uint32_t i = 0; i < attr_count; i++)
        {
            if (attr_list[i].id == SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS)
            {
                memcpy(nbr_mac, attr_list[i].value.mac, sizeof(sai_mac_t));
                no_mac = false;
                break;
            }
        }

        if (no_mac && !use_svi_mac)
        {
            SWSS_LOG_ERROR("No mac for BD ARP term neighbor %s", serializedObjectId.c_str());
            return SAI_STATUS_FAILURE;
        }

        /* Use SVI MAC for arp-term (proxy ARP), fall back to neighbor MAC */
        sai_mac_t *term_mac = use_svi_mac ? &svi_mac : &nbr_mac;

        init_vpp_client();

        switch (nbr_entry.ip_address.addr_family) {
        case SAI_IP_ADDR_FAMILY_IPV4:
            bd_ip_mac_add_del(bd_id, AF_INET,
                              &nbr_entry.ip_address.addr.ip4,
                              sizeof(nbr_entry.ip_address.addr.ip4),
                              *term_mac, true);
            break;
        case SAI_IP_ADDR_FAMILY_IPV6:
            bd_ip_mac_add_del(bd_id, AF_INET6,
                              nbr_entry.ip_address.addr.ip6,
                              sizeof(nbr_entry.ip_address.addr.ip6),
                              *term_mac, true);
            break;
        }

        SWSS_LOG_NOTICE("BD %d ARP term add for neighbor %s", bd_id,
                         serializedObjectId.c_str());

        /*
         * When using SVI MAC for arp-term (proxy ARP), traffic is directed
         * to the BVI's L3 path.  VPP needs an ip4/ip6 neighbor adjacency
         * on the BVI with the host's REAL MAC so it can do L3→L2 hairpin
         * forwarding (receive on BVI, lookup, send back into bridge domain
         * with the correct destination MAC).
         *
         * Without this, ip4-lookup finds the connected route on bvi10 but
         * has no adjacency to rewrite the MAC → packets are dropped.
         */
        if (use_svi_mac && !no_mac)
        {
            /* Skip L3 hairpin for self-referential entries (BVI's own IPs)
             * and broadcast — only program for remote hosts whose real MAC
             * differs from the SVI MAC */
            bool same_mac = (memcmp(nbr_mac, svi_mac, sizeof(sai_mac_t)) == 0);
            bool is_broadcast = true;
            for (int i = 0; i < 6; i++) {
                if (nbr_mac[i] != 0xff) { is_broadcast = false; break; }
            }

            if (!same_mac && !is_broadcast)
            {
                char bvi_ifname[32];
                snprintf(bvi_ifname, sizeof(bvi_ifname), "bvi%u", bd_id);

                char ip_str[INET6_ADDRSTRLEN] = {};
                char mac_str[18] = {};

                snprintf(mac_str, sizeof(mac_str),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         nbr_mac[0], nbr_mac[1], nbr_mac[2],
                         nbr_mac[3], nbr_mac[4], nbr_mac[5]);

                switch (nbr_entry.ip_address.addr_family) {
                case SAI_IP_ADDR_FAMILY_IPV4:
                {
                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_addr.s_addr = nbr_entry.ip_address.addr.ip4;
                    ip4_nbr_add_del(bvi_ifname, ~0, &sin, false, no_host_route, nbr_mac, true);

                    inet_ntop(AF_INET, &sin.sin_addr, ip_str, sizeof(ip_str));
                    SWSS_LOG_NOTICE("BD %d: programmed ip4 neighbor on %s for L3 hairpin "
                                    "(real MAC %s)", bd_id, bvi_ifname, mac_str);
                    break;
                }
                case SAI_IP_ADDR_FAMILY_IPV6:
                {
                    struct sockaddr_in6 sin6;
                    sin6.sin6_family = AF_INET6;
                    memcpy(sin6.sin6_addr.s6_addr, nbr_entry.ip_address.addr.ip6,
                           sizeof(sin6.sin6_addr.s6_addr));
                    ip6_nbr_add_del(bvi_ifname, ~0, &sin6, false, no_host_route, nbr_mac, true);

                    inet_ntop(AF_INET6, &sin6.sin6_addr, ip_str, sizeof(ip_str));
                    SWSS_LOG_NOTICE("BD %d: programmed ip6 neighbor on %s for L3 hairpin "
                                    "(real MAC %s)", bd_id, bvi_ifname, mac_str);
                    break;
                }
                }

                /*
                 * Also program a kernel static neighbor on the BVI tap
                 * (bvivlan<N>) with the host's REAL MAC.  Without this,
                 * kernel-originated traffic (e.g., ICMP echo replies to the
                 * BVI's own IP) would ARP on bvivlan<N> — but VPP's arp-term
                 * intercepts the ARP and replies with the SVI MAC.  When
                 * kernel uses SVI MAC as dst, VPP's l2-fwd sees it as the
                 * BVI's own MAC → reflection drop.
                 *
                 * With this static entry, the kernel uses the real host MAC
                 * directly, so the frame goes through l2-fwd to the correct
                 * bridge port (BondEthernet) instead of back to the BVI.
                 */
                if (ip_str[0] != '\0')
                {
                    char host_ifname[32];
                    snprintf(host_ifname, sizeof(host_ifname), "bvivlan%u", bd_id);

                    char cmd[256];
                    snprintf(cmd, sizeof(cmd),
                             "ip neigh replace %s lladdr %s dev %s nud permanent",
                             ip_str, mac_str, host_ifname);

                    if (system(cmd) == 0) {
                        SWSS_LOG_NOTICE("BD %d: programmed kernel neighbor on %s "
                                        "(%s -> %s) for kernel-originated replies",
                                        bd_id, host_ifname, ip_str, mac_str);
                    } else {
                        SWSS_LOG_WARN("BD %d: failed to program kernel neighbor "
                                      "on %s (%s -> %s)", bd_id, host_ifname,
                                      ip_str, mac_str);
                    }

                    /*
                     * Also program the neighbor on Vlan<N> (SONiC SVI) so
                     * FRR's zebra can see it and advertise EVPN Type-2 MAC/IP
                     * routes.  FRR watches Vlan<N> (not bvivlan<N>) for EVPN
                     * neighbor state.
                     */
                    char svi_ifname[32];
                    snprintf(svi_ifname, sizeof(svi_ifname), "Vlan%u", bd_id);

                    snprintf(cmd, sizeof(cmd),
                             "ip neigh replace %s lladdr %s dev %s nud reachable",
                             ip_str, mac_str, svi_ifname);

                    if (system(cmd) == 0) {
                        SWSS_LOG_NOTICE("BD %d: programmed kernel neighbor on %s "
                                        "(%s -> %s) for FRR EVPN Type-2 MAC/IP",
                                        bd_id, svi_ifname, ip_str, mac_str);
                    } else {
                        SWSS_LOG_WARN("BD %d: failed to program kernel neighbor "
                                      "on %s (%s -> %s)", bd_id, svi_ifname,
                                      ip_str, mac_str);
                    }
                }
            }
        }

        return SAI_STATUS_SUCCESS;
    }

    attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;

    CHECK_STATUS(get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, nbr_entry.rif_id, 1, &attr));

    if (objectTypeQuery(attr.value.oid) != SAI_OBJECT_TYPE_PORT)
    {
        return SAI_STATUS_SUCCESS;
    }
    auto port_oid = attr.value.oid;

    if (rif_type != SAI_ROUTER_INTERFACE_TYPE_SUB_PORT &&
        rif_type != SAI_ROUTER_INTERFACE_TYPE_PORT)
    {
        SWSS_LOG_NOTICE("Skipping neighbor add for attr type %d", rif_type);

        return SAI_STATUS_SUCCESS;
    }

    uint16_t vlan_id = 0;
    if (rif_type == SAI_ROUTER_INTERFACE_TYPE_SUB_PORT)
    {
        attr.id = SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID;

        CHECK_STATUS(get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, nbr_entry.rif_id, 1, &attr));
        vlan_id = attr.value.u16;
    }

    sai_mac_t nbr_mac;
    bool no_mac = true;

    if (is_add)
    {
        for (uint32_t i = 0; i < attr_count; i++)
        {
            switch (attr_list[i].id)
            {
            case SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS:
                memcpy(nbr_mac, attr_list[i].value.mac, sizeof(sai_mac_t));
                no_mac = false;
                break;

            default:
                break;
            }
        }
    } else {
        attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;

        if (get(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, serializedObjectId, 1, &attr) == SAI_STATUS_SUCCESS) {
            memcpy(nbr_mac, attr.value.mac, sizeof(sai_mac_t));
            no_mac = false;
        }
    }

    if (no_mac == true)
    {
        SWSS_LOG_ERROR("No mac address passed for neighbor %s", serializedObjectId.c_str());
        return SAI_STATUS_FAILURE;
    }

    std::string if_name;
    bool found = getTapNameFromPortId(port_oid, if_name);
    if (found == false)
    {
        SWSS_LOG_ERROR("host interface for port id %s not found", serializedObjectId.c_str());
        return SAI_STATUS_FAILURE;
    }

    const char *hwif_name = tap_to_hwif_name(if_name.c_str());
    const char *vpp_ifname;
    char subifname[32];

    if (vlan_id)
    {
        snprintf(subifname, sizeof(subifname), "%s.%u", hwif_name, vlan_id);

        vpp_ifname = subifname;
    } else {
        vpp_ifname = hwif_name;
    }
    init_vpp_client();

    switch (nbr_entry.ip_address.addr_family) {
    case SAI_IP_ADDR_FAMILY_IPV4:
        struct sockaddr_in sin;

        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = nbr_entry.ip_address.addr.ip4;

        ip4_nbr_add_del(vpp_ifname, ~0, &sin, false, no_host_route, nbr_mac, is_add);

        break;

    case SAI_IP_ADDR_FAMILY_IPV6:
        struct sockaddr_in6 sin6;

        sin6.sin6_family = AF_INET6;
        memcpy(sin6.sin6_addr.s6_addr, nbr_entry.ip_address.addr.ip6, sizeof(sin6.sin6_addr.s6_addr));

        ip6_nbr_add_del(vpp_ifname, ~0, &sin6, false, no_host_route, nbr_mac, is_add);

        break;
    }

    return SAI_STATUS_SUCCESS;
}

bool SwitchVpp::is_ip_nbr_active()
{
    SWSS_LOG_ENTER();

    if (nbr_env_read == false)
    {
        const char *val;

        val = getenv("NO_LINUX_NL");
        if (val && (*val == 'y' || *val == 'Y')) {
            nbr_active = true;
        }
        nbr_env_read = true;
    }
    return nbr_active;
}

sai_status_t SwitchVpp::addIpNbr(
        _In_ const std::string &serializedObjectId,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    if (is_ip_nbr_active() == true) {
        SWSS_LOG_NOTICE("Add neighbor in VS %s", serializedObjectId.c_str());
        addRemoveIpNbr(serializedObjectId, attr_count, attr_list, true);
    }

    CHECK_STATUS(create_internal(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, serializedObjectId, switch_id, attr_count, attr_list));

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeIpNbr(
        _In_ const std::string &serializedObjectId)
{
    SWSS_LOG_ENTER();

    if (is_ip_nbr_active() == true) {
        SWSS_LOG_NOTICE("Remove neighbor in VS %s", serializedObjectId.c_str());
        addRemoveIpNbr(serializedObjectId, 0, NULL, false);
    }

    CHECK_STATUS(remove_internal(SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, serializedObjectId));

    return SAI_STATUS_SUCCESS;
}
