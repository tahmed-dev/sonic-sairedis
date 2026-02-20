#include "SwitchVpp.h"
#include "FdbInfo.h"

#include "swss/exec.h"

#include "meta/sai_serialize.h"

#include "swss/logger.h"

#include "vppxlate/SaiVppXlate.h"

#include "SwitchVppUtils.h"

#include <memory>
#include <set>

using namespace saivs;

/**
 * @brief FDB_ENTRY FLUSH Modes.
 */
 typedef enum _fdb_flush_mode_t
 {
     FLUSH_BY_INTERFACE = 1, /* Flushing DYNAMIC FDB_ENTRY on Interface */
     FLUSH_BY_BD_ID = 2,     /* Flushing DYNAMIC FDB_ENTRY on Bridge */
     FLUSH_ALL = 4,          /* Flushing all DYNAMIC FDB_ENTRY on all */
 } fdb_flush_mode;

sai_status_t SwitchVpp::createVlanMember(
        _In_ sai_object_id_t object_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    auto sid = sai_serialize_object_id(object_id);

    CHECK_STATUS(create_internal(SAI_OBJECT_TYPE_VLAN_MEMBER, sid, switch_id, attr_count, attr_list));

    return vpp_create_vlan_member(attr_count, attr_list);

}

sai_status_t SwitchVpp::vpp_create_vlan_member(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    sai_object_id_t br_port_id;

    //find sw_if_index for given l2 interface
    auto attr_type = sai_metadata_get_attr_by_id(SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, attr_count, attr_list);

    if (attr_type == NULL)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID was not passed");

        return SAI_STATUS_FAILURE;
    }

    br_port_id = attr_type->value.oid;
    sai_object_type_t obj_type = objectTypeQuery(br_port_id);

    if (obj_type != SAI_OBJECT_TYPE_BRIDGE_PORT)
    {
        SWSS_LOG_ERROR("SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID=%s expected to be BRIDGE PORT but is: %s",
                sai_serialize_object_id(br_port_id).c_str(),
                sai_serialize_object_type(obj_type).c_str());

        return SAI_STATUS_FAILURE;
    }

    auto br_port_attrs = m_objectHash.at(SAI_OBJECT_TYPE_BRIDGE_PORT).at(sai_serialize_object_id(br_port_id));
    auto meta_type = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_BRIDGE_PORT, SAI_BRIDGE_PORT_ATTR_TYPE);
    auto it_type = br_port_attrs.find(meta_type->attridname);
    if (it_type != br_port_attrs.end()) {
        sai_bridge_port_type_t bp_type = (sai_bridge_port_type_t)it_type->second->getAttr()->value.s32;
        if (bp_type == SAI_BRIDGE_PORT_TYPE_TUNNEL) {
            SWSS_LOG_NOTICE("Skipping VLAN member VPP ops for tunnel bridge port %s",
                sai_serialize_object_id(br_port_id).c_str());
            return SAI_STATUS_SUCCESS;
        }
    }

    const char *hwifname = nullptr;
    uint32_t lag_swif_idx;

    auto meta = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_BRIDGE_PORT, SAI_BRIDGE_PORT_ATTR_PORT_ID);
    auto bp_attr = br_port_attrs[meta->attridname];
    auto port_id = bp_attr->getAttr()->value.oid;
    obj_type = objectTypeQuery(port_id);

    if (obj_type != SAI_OBJECT_TYPE_PORT && obj_type != SAI_OBJECT_TYPE_LAG )
    {
        SWSS_LOG_NOTICE("SAI_BRIDGE_PORT_ATTR_PORT_ID=%s expected to be PORT or LAG but is: %s",
                sai_serialize_object_id(port_id).c_str(),
                sai_serialize_object_type(obj_type).c_str());
        return SAI_STATUS_FAILURE;
    }

    if (obj_type == SAI_OBJECT_TYPE_PORT)
    {
        std::string if_name;
        bool found = getTapNameFromPortId(port_id, if_name);
        if (found == true)
        {
            hwifname = tap_to_hwif_name(if_name.c_str());
        }else {
            SWSS_LOG_NOTICE("No ports found for bridge port id :%s",sai_serialize_object_id(br_port_id).c_str());
            return SAI_STATUS_FAILURE;
        }
    } else if (obj_type == SAI_OBJECT_TYPE_LAG) {
        platform_bond_info_t bond_info;
        CHECK_STATUS(get_lag_bond_info(port_id, bond_info));
        lag_swif_idx = bond_info.sw_if_index;
        SWSS_LOG_NOTICE("lag swif idx :%d",lag_swif_idx);
	    hwifname =  vpp_get_swif_name(lag_swif_idx);
        SWSS_LOG_NOTICE("lag swif idx :%d swif_name:%s",lag_swif_idx, hwifname);
	    if (hwifname == NULL) {
            SWSS_LOG_NOTICE("LAG is not found for bridge port id :%s",sai_serialize_object_id(br_port_id).c_str());
            return SAI_STATUS_FAILURE;
	    }
    }

    auto attr_vlan_member = sai_metadata_get_attr_by_id(SAI_VLAN_MEMBER_ATTR_VLAN_ID, attr_count, attr_list);

    sai_object_id_t vlan_oid;

    if (attr_vlan_member == NULL)
    {
	    SWSS_LOG_NOTICE("attr SAI_VLAN_MEMBER_ATTR_VLAN_ID was not passed");
	    return SAI_STATUS_FAILURE;
    } else {
	    vlan_oid = attr_vlan_member->value.oid;
    }
    auto attr_vlanid_map = m_objectHash.at(SAI_OBJECT_TYPE_VLAN).at(sai_serialize_object_id(vlan_oid));
    auto md_vlan_id = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_VLAN, SAI_VLAN_ATTR_VLAN_ID);
    auto vlan_id =  attr_vlanid_map.at(md_vlan_id->attridname)->getAttr()->value.u16;

    if (vlan_id == 0)
    {
        SWSS_LOG_NOTICE("attr VLAN object id  was not passed");
        return SAI_STATUS_FAILURE;
    }

    uint32_t bridge_id = (uint32_t)vlan_id;
    auto attr_tag_mode = sai_metadata_get_attr_by_id(SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE, attr_count, attr_list);
    uint32_t tagging_mode = 0;
    const char *hw_ifname;
    char host_subifname[32];

    if (attr_tag_mode == NULL)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_MEMBER_ATTR_VLAN_ID was not passed");
        return SAI_STATUS_FAILURE;
    }

    tagging_mode = attr_tag_mode->value.u32;

    if (tagging_mode == SAI_VLAN_TAGGING_MODE_TAGGED)
    {
        /*
         create vpp subinterface and set it as bridge port
        */
        snprintf(host_subifname, sizeof(host_subifname), "%s.%u", hwifname, vlan_id);

        /* The host(tap) subinterface is also created as part of the vpp subinterface creation */
        create_sub_interface(hwifname, vlan_id, vlan_id);

        /* Get new list of physical interfaces from VS */
        refresh_interfaces_list();

        hw_ifname = host_subifname;

        //Create bridge and set the l2 port
        set_sw_interface_l2_bridge(hw_ifname,bridge_id, true, VPP_API_PORT_TYPE_NORMAL);

        //Set interface state up
        interface_set_state(hw_ifname, true);
    }
    else if (tagging_mode == SAI_VLAN_TAGGING_MODE_UNTAGGED)
    {
        hw_ifname = hwifname;

        //Create bridge and set the l2 port
        set_sw_interface_l2_bridge(hw_ifname,bridge_id, true, VPP_API_PORT_TYPE_NORMAL);

        //Set the vlan member to bridge and tags rewrite
        vpp_l2_vtr_op_t vtr_op = L2_VTR_PUSH_1;
        vpp_vlan_type_t push_dot1q = VLAN_DOT1Q;
        uint32_t tag1 = (uint32_t)vlan_id;
        uint32_t tag2 = ~0;
        set_l2_interface_vlan_tag_rewrite(hw_ifname, tag1, tag2, push_dot1q, vtr_op);
    }
    else {
        SWSS_LOG_ERROR("Tagging Mode %d not implemented", tagging_mode);
        return SAI_STATUS_FAILURE;
    }


    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeVlanMember(
        _In_ sai_object_id_t objectId)
{
    SWSS_LOG_ENTER();

    vpp_remove_vlan_member(objectId);

    auto sid = sai_serialize_object_id(objectId);

    CHECK_STATUS(remove_internal(SAI_OBJECT_TYPE_VLAN_MEMBER, sid));

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_remove_vlan_member(
        _In_ sai_object_id_t vlan_member_oid)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;

    attr.id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;

    sai_status_t status = get(SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_oid, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_MEMBER_ATTR_VLAN_ID is not present");

        return SAI_STATUS_FAILURE;
    }
    sai_object_id_t vlan_oid = attr.value.oid;

    sai_object_type_t obj_type = objectTypeQuery(vlan_oid);

    if (obj_type != SAI_OBJECT_TYPE_VLAN)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_MEMBER_ATTR_VLAN_ID is not valid");
        return SAI_STATUS_FAILURE;
    }

    attr.id = SAI_VLAN_ATTR_VLAN_ID;
    status = get(SAI_OBJECT_TYPE_VLAN, vlan_oid, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_ATTR_VLAN_ID is not present");

        return SAI_STATUS_FAILURE;
    }
    auto vlan_id = attr.value.u16;
    uint32_t bridge_id = (uint32_t)vlan_id;

    attr.id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
    status = get(SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_oid, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID is not present");
        return SAI_STATUS_FAILURE;
    }

    sai_object_id_t br_port_oid = attr.value.oid;

    obj_type = objectTypeQuery(br_port_oid);
    if (obj_type != SAI_OBJECT_TYPE_BRIDGE_PORT)
    {
        SWSS_LOG_ERROR("SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID=%s expected to be BRIDGE PORT but is: %s",
                sai_serialize_object_id(br_port_oid).c_str(),
                sai_serialize_object_type(obj_type).c_str());

        return SAI_STATUS_FAILURE;
    }

    const char *hw_ifname = nullptr;
    auto br_port_attrs = m_objectHash.at(SAI_OBJECT_TYPE_BRIDGE_PORT).at(sai_serialize_object_id(br_port_oid));
    auto meta = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_BRIDGE_PORT, SAI_BRIDGE_PORT_ATTR_PORT_ID);
    auto bp_attr = br_port_attrs[meta->attridname];
    auto port_id = bp_attr->getAttr()->value.oid;
    obj_type = objectTypeQuery(port_id);

    if (obj_type != SAI_OBJECT_TYPE_PORT && obj_type != SAI_OBJECT_TYPE_LAG)
    {
        SWSS_LOG_NOTICE("SAI_BRIDGE_PORT_ATTR_PORT_ID=%s expected to be PORT or LAG but is: %s",
                sai_serialize_object_id(port_id).c_str(),
                sai_serialize_object_type(obj_type).c_str());
        return SAI_STATUS_FAILURE;
    }

    if (obj_type == SAI_OBJECT_TYPE_PORT)
    {
        std::string if_name;
        bool found = getTapNameFromPortId(port_id, if_name);
        if (found == true)
        {
            hw_ifname = tap_to_hwif_name(if_name.c_str());
        }else {
            SWSS_LOG_NOTICE("No ports found for bridge port id :%s",sai_serialize_object_id(br_port_oid).c_str());
            return SAI_STATUS_FAILURE;
        }
    } else if (obj_type == SAI_OBJECT_TYPE_LAG) {
        platform_bond_info_t bond_info;
        CHECK_STATUS(get_lag_bond_info(port_id, bond_info));
        uint32_t lag_swif_idx = bond_info.sw_if_index;
        SWSS_LOG_NOTICE("lag swif idx :%d",lag_swif_idx);
	    hw_ifname =  vpp_get_swif_name(lag_swif_idx);
        SWSS_LOG_NOTICE("lag swif idx :%d swif_name:%s",lag_swif_idx, hw_ifname);
	    if (hw_ifname == NULL) {
            SWSS_LOG_NOTICE("LAG port is not found for bridge port id :%s",sai_serialize_object_id(port_id).c_str());
            return SAI_STATUS_FAILURE;
	    }
    }

    attr.id = SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE;
    status = get(SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_oid, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE is not present");

        return SAI_STATUS_FAILURE;
    }

    uint32_t tagging_mode = attr.value.s32;
    char host_subifname[32];
    if (tagging_mode == SAI_VLAN_TAGGING_MODE_UNTAGGED)
    {

        //First disable tag-rewrite.
        vpp_l2_vtr_op_t vtr_op =L2_VTR_DISABLED;
        vpp_vlan_type_t push_dot1q = VLAN_DOT1Q;
        uint32_t tag1 = (uint32_t)vlan_id;
        uint32_t tag2 = ~0;
        set_l2_interface_vlan_tag_rewrite(hw_ifname, tag1, tag2, push_dot1q, vtr_op);

        //Remove interface from bridge, interface type should be changed to others types like l3.
        set_sw_interface_l2_bridge(hw_ifname, bridge_id, false, VPP_API_PORT_TYPE_NORMAL);
    }
    else if (tagging_mode == SAI_VLAN_TAGGING_MODE_TAGGED)
    {

        // set interface l2 tag-rewrite GigabitEthernet0/8/0.200 disable
        snprintf(host_subifname, sizeof(host_subifname), "%s.%u", hw_ifname, vlan_id);
        hw_ifname = host_subifname;
        // Remove the l2 port from bridge
        set_sw_interface_l2_bridge(hw_ifname, bridge_id, false, VPP_API_PORT_TYPE_NORMAL);

        // delete subinterface
        delete_sub_interface(hw_ifname, vlan_id);

        // Get new list of physical interfaces from VS
        refresh_interfaces_list();
    }
    else {

        SWSS_LOG_ERROR("Tagging mode %d not implemented", tagging_mode);
        return SAI_STATUS_FAILURE;
    }

    //Check if the bridge has zero ports left, if so remove the bridge as well
    uint32_t member_count = 0;
    bridge_domain_get_member_count (bridge_id, &member_count);
    if (member_count == 0)
    {
        vpp_bridge_domain_add_del(bridge_id, false);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_create_bvi_interface(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    auto attr_vlan_oid = sai_metadata_get_attr_by_id(SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, attr_count, attr_list);

    if (attr_vlan_oid == NULL)
    {
        SWSS_LOG_ERROR("attr SAI_ROUTER_INTERFACE_ATTR_VLAN_ID was not passed");
        return SAI_STATUS_SUCCESS;
    }

    sai_object_id_t vlan_oid = attr_vlan_oid->value.oid;

    sai_object_type_t obj_type = objectTypeQuery(vlan_oid);

    if (obj_type != SAI_OBJECT_TYPE_VLAN)
    {
        SWSS_LOG_ERROR(" VLAN object type was not passed");
        return SAI_STATUS_SUCCESS;
    }
    auto vlan_attrs = m_objectHash.at(SAI_OBJECT_TYPE_VLAN).at(sai_serialize_object_id(vlan_oid));
    auto md_vlan_id = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_VLAN, SAI_VLAN_ATTR_VLAN_ID);
    auto vlan_id = (uint32_t) vlan_attrs.at(md_vlan_id->attridname)->getAttr()->value.u16;

    if (vlan_id == 0)
    {
	    SWSS_LOG_NOTICE("attr VLAN object id  was not passed");
	    return SAI_STATUS_FAILURE;
    }

    auto attr_mac_addr = sai_metadata_get_attr_by_id(SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, attr_count, attr_list);
    if (attr_mac_addr == NULL)
    {
	    SWSS_LOG_NOTICE("attr ROUTER INTERFACE MAC Address is not found");
	    return SAI_STATUS_FAILURE;
    }

    sai_mac_t mac_addr;
    memcpy(mac_addr, attr_mac_addr->value.mac, sizeof(sai_mac_t));

    //Create BVI interface
    create_bvi_interface(mac_addr,vlan_id);

    // Get new list of physical interfaces from VS
    refresh_interfaces_list();

    char hw_bviifname[32];
    const char *hw_ifname;
    snprintf(hw_bviifname, sizeof(hw_bviifname), "bvi%u",vlan_id);
    hw_ifname = hw_bviifname;

    //Create bridge and set the l2 port as BVI
    set_sw_interface_l2_bridge(hw_ifname,vlan_id, true, VPP_API_PORT_TYPE_BVI);

    //Set interface state up
    interface_set_state(hw_ifname, true);

    //Set the bvi as access or untagged port of the bridge
    vpp_l2_vtr_op_t vtr_op = L2_VTR_PUSH_1;
    vpp_vlan_type_t push_dot1q = VLAN_DOT1Q;
    uint32_t tag1 = (uint32_t)vlan_id;
    uint32_t tag2 = ~0;
    set_l2_interface_vlan_tag_rewrite(hw_ifname, tag1, tag2, push_dot1q, vtr_op);

    //Set the arp termination for bridge
    uint32_t bd_id = (uint32_t) vlan_id;
    set_bridge_domain_flags(bd_id, VPP_BD_FLAG_ARP_TERM,true);

    /*
     * NOTE: BVI LCP pair creation is deferred. VPP's configure_lcp_interface
     * tries to create a new tap device named "Vlan<N>", but that interface
     * already exists in the Linux kernel (created by SONiC bridge/VLAN
     * subsystem). VPP's tap_create_if fails with TUNSETIFF: Invalid argument.
     * A different punt/inject mechanism is needed for BVI ↔ kernel Vlan.
     */

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_delete_bvi_interface(
        _In_ sai_object_id_t bvi_obj_id)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attr;

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    sai_status_t status = get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, bvi_obj_id, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_ROUTER_INTERFACE_ATTR_TYPE is not present");
        return SAI_STATUS_FAILURE;
    }

    if (attr.value.s32 != SAI_ROUTER_INTERFACE_TYPE_VLAN)
    {
        SWSS_LOG_ERROR("attr SAI_ROUTER_INTERFACE_ATTR_TYPE is not VLAN");
        return SAI_STATUS_FAILURE;
    }

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VLAN_ID;
    status = get(SAI_OBJECT_TYPE_ROUTER_INTERFACE, bvi_obj_id, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_ROUTER_INTERFACE_ATTR_VLAN_ID is not present");
        return SAI_STATUS_FAILURE;
    }

    sai_object_id_t vlan_oid = attr.value.oid;
    sai_object_type_t obj_type = objectTypeQuery(vlan_oid);

    if (obj_type != SAI_OBJECT_TYPE_VLAN)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_MEMBER_ATTR_VLAN_ID is not valid");
        return SAI_STATUS_FAILURE;
    }

    attr.id = SAI_VLAN_ATTR_VLAN_ID;
    status = get(SAI_OBJECT_TYPE_VLAN, vlan_oid, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_VLAN_ATTR_VLAN_ID is not present");
        return SAI_STATUS_FAILURE;
    }
    auto vlan_id = attr.value.u16;
    char hw_bviifname[32];
    const char *hw_ifname;
    snprintf(hw_bviifname, sizeof(hw_bviifname), "bvi%u",vlan_id);
    hw_ifname = hw_bviifname;

    //Disable arp termination for bridge
    uint32_t bd_id = (uint32_t) vlan_id;
    set_bridge_domain_flags(bd_id, VPP_BD_FLAG_ARP_TERM, false);

    //First disable tag-rewrite.
    vpp_l2_vtr_op_t vtr_op = L2_VTR_DISABLED;
    vpp_vlan_type_t push_dot1q = VLAN_DOT1Q;
    uint32_t tag1 = (uint32_t)vlan_id;
    uint32_t tag2 = ~0;
    set_l2_interface_vlan_tag_rewrite(hw_ifname, tag1, tag2, push_dot1q, vtr_op);

    //Remove interface from bridge, interface type should be changed to others types like l3.
    set_sw_interface_l2_bridge(hw_ifname, bd_id, false, VPP_API_PORT_TYPE_BVI);

    //Remove the bvi interface
    delete_bvi_interface(hw_ifname);

    // refresh interfaces from VS
    refresh_interfaces_list();

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::get_lag_bond_info(const sai_object_id_t lag_id, platform_bond_info_t &bond_info)
{
    SWSS_LOG_ENTER();

    auto it = m_lag_bond_map.find(lag_id);
    if (it == m_lag_bond_map.end())
    {
        SWSS_LOG_ERROR("failed to find bond info for lag id: %s", sai_serialize_object_id(lag_id).c_str());
        return SAI_STATUS_ITEM_NOT_FOUND;
    }
    bond_info = it->second;
    return SAI_STATUS_SUCCESS;
}

int SwitchVpp::remove_lag_to_bond_entry(const sai_object_id_t lag_oid)
{
    SWSS_LOG_ENTER();

    auto it = m_lag_bond_map.find(lag_oid);

    if (it == m_lag_bond_map.end())
    {
        SWSS_LOG_ERROR("failed to find lag swif index for : %s", sai_serialize_object_id(lag_oid).c_str());
        return ~0;
    }

    SWSS_LOG_NOTICE("Removing lag object swif index: %s", sai_serialize_object_id(lag_oid).c_str());
    m_lag_bond_map.erase(it);
    return 0;
}

sai_status_t SwitchVpp::createLag(
        _In_ sai_object_id_t object_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    auto sid = sai_serialize_object_id(object_id);
    CHECK_STATUS(create_internal(SAI_OBJECT_TYPE_LAG, sid, switch_id, attr_count, attr_list));
    return vpp_create_lag(object_id, attr_count, attr_list);

}

/*
 * This function determines the ID of a newly created PortChannel.
 * It does this by querying the list of PortChannels using the ip command and
 * comparing it to the existing LAG interfaces in m_lag_bond_map.
 *
 * This function is necessary due to the way IP addresses are set on interfaces in Sonic-VPP,
 * which requires mapping between the PortChannel interface and the BondEthernet in VPP.
 * Although no issues have been observed during manual and sonic-mgmt testing,
 * it should be noted that this design may theoretically present a race condition,
 * where the wrong ID is returned for a given LAG interface if multiple PortChannels are created concurrently.
 */
uint32_t SwitchVpp::find_new_bond_id()
{
    SWSS_LOG_ENTER();

    std::stringstream cmd;
    std::string res;
    uint32_t bond_id = ~0;

    // Get list of PortChannels from ip command
    cmd << IP_CMD << " -o link show | awk -F': ' '{print $2}' | grep " << PORTCHANNEL_PREFIX;

    int ret = swss::exec(cmd.str(), res);
    if (ret) {
        SWSS_LOG_ERROR("Command '%s' failed with rc %d", cmd.str().c_str(), ret);
        return ~0;
    }

    if (res.length() == 0) {
        SWSS_LOG_ERROR("No PortChannels found in output of command '%s': %s", cmd.str().c_str(), res.c_str());
        return ~0;
    }

    SWSS_LOG_DEBUG("Output of ip command: %s", res.c_str());

    std::unordered_set<uint32_t> existing_bond_ids;
    for (const auto& entry : m_lag_bond_map) {
        existing_bond_ids.insert(entry.second.id);
    }

    std::istringstream iss(res);
    std::string line;
    bool found_new_bond_id = false;
    while (std::getline(iss, line)) {
        std::string portchannel_name = line.substr(0, line.find('\n'));
        bond_id = std::stoi(portchannel_name.substr(strlen(PORTCHANNEL_PREFIX)));

        if (existing_bond_ids.find(bond_id) == existing_bond_ids.end()) {
            SWSS_LOG_NOTICE("Found new bond id from PortChannel name: %d", bond_id);
            found_new_bond_id = true;
            break;
        }
    }

    return found_new_bond_id ? bond_id : ~0;
}

sai_status_t SwitchVpp::vpp_create_lag(
        _In_ sai_object_id_t lag_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    uint32_t mode, lb;
    uint32_t bond_id = ~0;
    uint32_t swif_idx = ~0;
    const char *hw_ifname;

    // Extract bond_id from PortChannel name
    bond_id = find_new_bond_id();
    if (bond_id == static_cast<uint32_t>(~0))
    {
        SWSS_LOG_ERROR("Bond id could not be found");
        return SAI_STATUS_FAILURE;
    }

    // Set mode and lb. SONiC config does not have provision to pass mode and load balancing algorithm
    mode = VPP_BOND_API_MODE_XOR;
    lb = VPP_BOND_API_LB_ALGO_L34;

    create_bond_interface(bond_id, mode, lb, &swif_idx);
    if (swif_idx == static_cast<uint32_t>(~0))
    {
        SWSS_LOG_ERROR("failed to create bond interface in VPP for %s", sai_serialize_object_id(lag_id).c_str());
        return SAI_STATUS_FAILURE;
    }

    // Update the lag to bond map
    platform_bond_info_t bond_info = {swif_idx, bond_id, false};
    m_lag_bond_map[lag_id] = bond_info;
    SWSS_LOG_NOTICE("vpp bond interface created for lag_id:%s, swif index:%d, bond_id:%d\n", sai_serialize_object_id(lag_id).c_str(), swif_idx, bond_id);
    refresh_interfaces_list();

    // Set the bond interface state up
    hw_ifname = vpp_get_swif_name(swif_idx);
    SWSS_LOG_NOTICE("Setting lag hw interface state to up :%s",hw_ifname);
    interface_set_state(hw_ifname, true);
    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeLag(
        _In_ sai_object_id_t lag_oid)
{
    SWSS_LOG_ENTER();

    CHECK_STATUS_QUIET(vpp_remove_lag(lag_oid));
    auto sid = sai_serialize_object_id(lag_oid);
    CHECK_STATUS(remove_internal(SAI_OBJECT_TYPE_LAG, sid));
    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_remove_lag(
        _In_ sai_object_id_t lag_oid)
{
    SWSS_LOG_ENTER();

    int ret;
    platform_bond_info_t bond_info;

    CHECK_STATUS(get_lag_bond_info(lag_oid, bond_info));
    uint32_t lag_swif_idx = bond_info.sw_if_index;
    auto lag_ifname =  vpp_get_swif_name(lag_swif_idx);
    SWSS_LOG_NOTICE("lag swif idx :%d swif_name:%s",lag_swif_idx, lag_ifname);
    if (lag_ifname == NULL)
    {
        SWSS_LOG_NOTICE("LAG interface name is not found for LAG PORT :%s",sai_serialize_object_id(lag_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    //Delete the Bond interface (also deletes the lcp pair)
    ret = delete_bond_interface(lag_ifname);
    if (ret != 0)
    {
        SWSS_LOG_ERROR("failed to delete bond interface in VPP for %s", sai_serialize_object_id(lag_oid).c_str());
        return SAI_STATUS_FAILURE;
    }
    remove_lag_to_bond_entry(lag_oid);
    refresh_interfaces_list();

    return SAI_STATUS_SUCCESS;
}


sai_status_t SwitchVpp::createLagMember(
        _In_ sai_object_id_t object_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    auto sid = sai_serialize_object_id(object_id);

    CHECK_STATUS(create_internal(SAI_OBJECT_TYPE_LAG_MEMBER, sid, switch_id, attr_count, attr_list));
    return vpp_create_lag_member(attr_count, attr_list);
}

sai_status_t SwitchVpp::vpp_create_lag_member(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    bool is_long_timeout = false;
    bool is_passive = false;
    int ret;
    uint32_t bond_if_idx;
    uint32_t bond_id;
    sai_object_id_t lag_oid, lag_port_oid;

    //Get the bond interface index from attr SAI_LAG_MEMBER_ATTR_LAG_ID
    auto attr_type = sai_metadata_get_attr_by_id(SAI_LAG_MEMBER_ATTR_LAG_ID, attr_count, attr_list);
    if (attr_type == NULL)
    {
        SWSS_LOG_ERROR("attr SAI_LAG_MEMBER_ATTR_LAG_ID was not passed");
        return SAI_STATUS_FAILURE;
    }
    lag_oid = attr_type->value.oid;
    sai_object_type_t obj_type = objectTypeQuery(lag_oid);

    if (obj_type != SAI_OBJECT_TYPE_LAG)
    {
        SWSS_LOG_ERROR(" SAI_LAG_MEMBER_ATTR_LAG_ID = %s expected to be LAG ID but is: %s",
                sai_serialize_object_id(lag_oid).c_str(),
                sai_serialize_object_type(obj_type).c_str());
        return SAI_STATUS_FAILURE;
    }

    platform_bond_info_t bond_info;
    CHECK_STATUS(get_lag_bond_info(lag_oid, bond_info));
    bond_if_idx = bond_info.sw_if_index;
    SWSS_LOG_NOTICE("bond if index is %d\n", bond_if_idx);

    attr_type = sai_metadata_get_attr_by_id(SAI_LAG_MEMBER_ATTR_PORT_ID, attr_count, attr_list);

    if (attr_type == NULL)
    {
        SWSS_LOG_ERROR("attr SAI_LAG_MEMBER_ATTR_PORT_ID was not present\n");
        return SAI_STATUS_FAILURE;
    }

    lag_port_oid = attr_type->value.oid;
    SWSS_LOG_NOTICE("lag port id is %s",sai_serialize_object_id(lag_port_oid).c_str());
    obj_type = objectTypeQuery(lag_port_oid);
    if (obj_type != SAI_OBJECT_TYPE_PORT)
    {
        SWSS_LOG_NOTICE("SAI_BRIDGE_PORT_ATTR_PORT_ID=%s expected to be PORT but is: %s",
                sai_serialize_object_id(lag_port_oid).c_str(),
                sai_serialize_object_type(obj_type).c_str());
        return SAI_STATUS_FAILURE;
    }

    std::string if_name;
    bool found = getTapNameFromPortId(lag_port_oid, if_name);
    const char *hwifname;
    if (found == true)
    {
        hwifname = tap_to_hwif_name(if_name.c_str());
        SWSS_LOG_NOTICE("hwif name for port is %s",hwifname);
    }else {
        SWSS_LOG_NOTICE("No ports found for lag port id :%s",sai_serialize_object_id(lag_port_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    ret = create_bond_member(bond_if_idx, hwifname, is_passive, is_long_timeout);
    if (ret != 0)
    {
        SWSS_LOG_ERROR("failed to add bond member in VPP for %s", sai_serialize_object_id(lag_port_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    if (!bond_info.lcp_created) {
        // create tap and lcp for the Bond intf after first member is added to ensure tap mac = member mac = bond mac
        std::ostringstream tap_stream;
        bond_id = bond_info.id;
        tap_stream << "be" << bond_id;
        std::string tap = tap_stream.str();

        const char *hw_ifname;
        hw_ifname = vpp_get_swif_name(bond_if_idx);
        configure_lcp_interface(hw_ifname, tap.c_str(), true);

        // add tc filter to redirect traffic from tap to PortChannel
        std::string portchannel = std::string("PortChannel") + std::to_string(bond_id);
        std::string be = std::string("be") + std::to_string(bond_id);
        CHECK_STATUS(add_tc_filter_redirect(be, portchannel));

        // update the lag to bond map
        bond_info.lcp_created = true;
        m_lag_bond_map[lag_oid] = bond_info;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeLagMember(
        _In_ sai_object_id_t lag_member_oid)
{
    SWSS_LOG_ENTER();

    CHECK_STATUS_QUIET(vpp_remove_lag_member(lag_member_oid));

    auto sid = sai_serialize_object_id(lag_member_oid);

    CHECK_STATUS(remove_internal(SAI_OBJECT_TYPE_LAG_MEMBER, sid));

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_remove_lag_member(
        _In_ sai_object_id_t lag_member_oid)
{
    SWSS_LOG_ENTER();

    int ret;

    sai_attribute_t attr;

    attr.id = SAI_LAG_MEMBER_ATTR_LAG_ID;

    sai_status_t status = get(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_oid, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_LAG_MEMBER_ATTR_LAG_ID is not present");

        return SAI_STATUS_FAILURE;
    }
    sai_object_id_t lag_oid = attr.value.oid;

    sai_object_type_t obj_type = objectTypeQuery(lag_oid);

    if (obj_type != SAI_OBJECT_TYPE_LAG)
    {
        SWSS_LOG_ERROR("attr SAI_LAG_MEMBER_ATTR_LAG_ID is not valid");
        return SAI_STATUS_FAILURE;
    }

    attr.id = SAI_LAG_MEMBER_ATTR_PORT_ID;

    status = get(SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_oid, 1, &attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("attr SAI_LAG_MEMBER_ATTR_PORT_ID is not present");

        return SAI_STATUS_FAILURE;
    }
    sai_object_id_t port_oid = attr.value.oid;

    obj_type = objectTypeQuery(port_oid);

    if (obj_type != SAI_OBJECT_TYPE_PORT)
    {
        SWSS_LOG_ERROR("attr SAI_LAG_MEMBER_ATTR_PORT_ID is not valid");
        return SAI_STATUS_FAILURE;
    }

    std::string if_name;
    bool found = getTapNameFromPortId(port_oid, if_name);
    const char *lag_member_ifname;
    if (found == true)
    {
        lag_member_ifname = tap_to_hwif_name(if_name.c_str());
	SWSS_LOG_NOTICE("hwif name for port is %s",lag_member_ifname);
    } else {
        SWSS_LOG_NOTICE("No ports found for lag port id :%s",sai_serialize_object_id(port_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    ret = delete_bond_member(lag_member_ifname);
    if (ret != 0)
    {
        SWSS_LOG_ERROR("failed to delete bond member in VPP for %s", sai_serialize_object_id(port_oid).c_str());
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::FdbEntryadd(
        _In_ const std::string &serializedObjectId,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    CHECK_STATUS(create_internal(SAI_OBJECT_TYPE_FDB_ENTRY, serializedObjectId, switch_id, attr_count, attr_list));

    vpp_fdbentry_add(serializedObjectId, switch_id, attr_count, attr_list);

    return SAI_STATUS_SUCCESS;

}

sai_status_t SwitchVpp::FdbEntrydel(
        _In_ const std::string &serializedObjectId)
{
    SWSS_LOG_ENTER();

    vpp_fdbentry_del(serializedObjectId);

    CHECK_STATUS(remove_internal(SAI_OBJECT_TYPE_FDB_ENTRY, serializedObjectId));

    return SAI_STATUS_SUCCESS;

}

sai_status_t SwitchVpp::vpp_fdbentry_add(
        _In_ const std::string &serializedObjectId,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{

    SWSS_LOG_ENTER();

    sai_fdb_entry_t fdb_entry;
    sai_deserialize_fdb_entry(serializedObjectId, fdb_entry);

    /* Attribute#1 */
    auto attr_type = sai_metadata_get_attr_by_id(SAI_FDB_ENTRY_ATTR_TYPE, attr_count, attr_list);

    if (attr_type == NULL)
    {
        SWSS_LOG_ERROR("attr SAI_FDB_ENTRY_ATTR_TYPE was not passed");

        return SAI_STATUS_FAILURE;
    }

    bool is_static = (attr_type->value.s32 == SAI_FDB_ENTRY_TYPE_STATIC ? true : false);
    bool is_add = true; /* Adding the entry in FDB*/

    /* Attribute#2 */
    sai_object_id_t br_port_id;
    sai_object_id_t port_id;

    attr_type = sai_metadata_get_attr_by_id(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, attr_count, attr_list);

    if (attr_type == NULL)
    {
        SWSS_LOG_ERROR("attr SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID was not passed");

        return SAI_STATUS_FAILURE;
    }

    br_port_id = attr_type->value.oid;
    sai_object_type_t obj_type = objectTypeQuery(br_port_id);

    if (obj_type != SAI_OBJECT_TYPE_BRIDGE_PORT)
    {
        SWSS_LOG_ERROR("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID=%s expected to be PORT but is: %s",
                sai_serialize_object_id(br_port_id).c_str(),
                sai_serialize_object_type(obj_type).c_str());

        return SAI_STATUS_FAILURE;
    }

    auto br_port_attrs = m_objectHash.at(SAI_OBJECT_TYPE_BRIDGE_PORT).at(sai_serialize_object_id(br_port_id));
    auto meta = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_BRIDGE_PORT, SAI_BRIDGE_PORT_ATTR_PORT_ID);
    auto bp_attr = br_port_attrs[meta->attridname];
    port_id = bp_attr->getAttr()->value.oid;
    obj_type = objectTypeQuery(port_id);

    if (obj_type != SAI_OBJECT_TYPE_PORT)
    {
        SWSS_LOG_NOTICE("SAI_BRIDGE_PORT_ATTR_PORT_ID=%s expected to be PORT but is: %s",
                sai_serialize_object_id(port_id).c_str(),
                sai_serialize_object_type(obj_type).c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Need to extract the VLAN ID attached based on the Port_ID */
    sai_attribute_t attr;
    attr.id = SAI_PORT_ATTR_PORT_VLAN_ID;

    sai_status_t get_status = get(SAI_OBJECT_TYPE_PORT, port_id, 1, &attr);

    if (get_status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("failed to get port vlan id from port %s",
                sai_serialize_object_id(port_id).c_str());
        return SAI_STATUS_FAILURE;
    }

    uint32_t bd_id = attr.value.u16; /* bd_id is same as VLAN ID for .1Q bridge */

    std::string ifname;
    if (vpp_get_hwif_name(port_id, 0, ifname) == true)
    {
        const char *hwif_name = ifname.c_str();
        auto ret = l2fib_add_del(hwif_name, fdb_entry.mac_address, bd_id, is_add, is_static);
        SWSS_LOG_NOTICE("FDB Entry Added on hwif_name %s Successful ret_val: %d", hwif_name, ret);

    }
    else
    {
        SWSS_LOG_ERROR("FDB_ENTRY failed because of INVALID PORT_ID");

        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_fdbentry_del(
        _In_ const std::string &serializedObjectId)
{
    SWSS_LOG_ENTER();

    sai_fdb_entry_t fdb_entry;
    sai_deserialize_fdb_entry(serializedObjectId, fdb_entry);

    sai_object_id_t br_port_id;
    sai_object_id_t port_id;
    bool is_static = false;

    sai_attribute_t attr_list[2];
    /* Attribute#1 */
    attr_list[0].id = SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID;
    /* Attribute#2 */
    attr_list[1].id = SAI_FDB_ENTRY_ATTR_TYPE;

    if (get(SAI_OBJECT_TYPE_FDB_ENTRY, serializedObjectId, 1, &attr_list[0]) == SAI_STATUS_SUCCESS)
    {
       if (SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID == attr_list[0].id)
        {
            br_port_id = attr_list[0].value.oid;
        }
        else
        {
            SWSS_LOG_ERROR("DELETE FDB_ENTRY failed because of INVALID ATTR BRIDGE_PORT_ID");
            return SAI_STATUS_FAILURE;
        }

        if (get(SAI_OBJECT_TYPE_FDB_ENTRY, serializedObjectId, 1, &attr_list[1]) == SAI_STATUS_SUCCESS)
        {
            if (SAI_FDB_ENTRY_ATTR_TYPE == attr_list[1].id )
            {
                is_static = (attr_list[1].value.s32 == SAI_FDB_ENTRY_TYPE_STATIC ? true : false);
            }
            else
            {
                SWSS_LOG_ERROR("DELETE FDB_ENTRY failed because of INVALID ATTR ENTRY TYPE");
                return SAI_STATUS_FAILURE;
            }
        }
    }
    else
    {
        SWSS_LOG_ERROR(" Invaid Attribute IDs passed for DELETE FDB_ENTRY");
        return SAI_STATUS_FAILURE;
    }
    bool is_add = false; /* Deleting the entry in FDB*/

    sai_object_type_t obj_type = objectTypeQuery(br_port_id);
    if (obj_type != SAI_OBJECT_TYPE_BRIDGE_PORT)
    {
        SWSS_LOG_ERROR("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID=%s expected to be PORT but is: %s",
                sai_serialize_object_id(br_port_id).c_str(),
                sai_serialize_object_type(obj_type).c_str());

        return SAI_STATUS_FAILURE;
    }

    auto br_port_attrs = m_objectHash.at(SAI_OBJECT_TYPE_BRIDGE_PORT).at(sai_serialize_object_id(br_port_id));
    auto meta = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_BRIDGE_PORT, SAI_BRIDGE_PORT_ATTR_PORT_ID);
    auto bp_attr = br_port_attrs[meta->attridname];
    port_id = bp_attr->getAttr()->value.oid;
    obj_type = objectTypeQuery(port_id);

    if (obj_type != SAI_OBJECT_TYPE_PORT)
    {
        SWSS_LOG_ERROR("SAI_BRIDGE_PORT_ATTR_PORT_ID=%s expected to be PORT but is: %s",
                sai_serialize_object_id(port_id).c_str(),
                sai_serialize_object_type(obj_type).c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Need the VLAN ID attached based on the Port_ID */
    sai_attribute_t attr;
    attr.id = SAI_PORT_ATTR_PORT_VLAN_ID;

    sai_status_t get_status = get(SAI_OBJECT_TYPE_PORT, port_id, 1, &attr);

    if (get_status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("failed to get port vlan id from port %s",
                sai_serialize_object_id(port_id).c_str());
        return SAI_STATUS_FAILURE;
    }

    uint32_t bd_id = attr.value.u16; /* bd_id is same as VLAN ID for .1Q bridge */

    std::string ifname;

    if (vpp_get_hwif_name(port_id, 0, ifname) == true)
    {
        const char *hwif_name = ifname.c_str();
        auto ret = l2fib_add_del(hwif_name, fdb_entry.mac_address, bd_id, is_add, is_static);
        SWSS_LOG_NOTICE(" Delete FDB_ENTRY on hwif_name %s Successful ret_val: %d", hwif_name, ret);

    }
    else
    {
        SWSS_LOG_ERROR("FDB entry Delete: Invalid ObjectID for the hwif on this bridge");

        return SAI_STATUS_FAILURE;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::vpp_fdbentry_flush(
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    sai_attribute_t attribute;
    sai_object_id_t br_port_id = 0;
    sai_object_id_t port_id;
    uint32_t bd_id = 0;
    uint8_t mode = 0;
    bool is_static_entry = false;

    for (uint32_t i = 0; i < attr_count; i++)
    {
        attribute = attr_list[i];
        switch (attribute.id)
        {
            case SAI_FDB_FLUSH_ATTR_BRIDGE_PORT_ID:
                {
                    mode |= FLUSH_BY_INTERFACE;
                    br_port_id = attribute.value.oid;
                    sai_object_type_t obj_type = objectTypeQuery(br_port_id);

                    if (obj_type != SAI_OBJECT_TYPE_BRIDGE_PORT)
                    {
                        SWSS_LOG_ERROR("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID=%s expected to be PORT but is: %s",
                                sai_serialize_object_id(br_port_id).c_str(),
                                sai_serialize_object_type(obj_type).c_str());

                        return SAI_STATUS_FAILURE;
                    }
                }
                break;

            case SAI_FDB_FLUSH_ATTR_BV_ID:
                {
                    mode |= FLUSH_BY_BD_ID;
                    bd_id = attribute.value.u16;
                }
                break;

            case SAI_FDB_FLUSH_ATTR_ENTRY_TYPE:
                {
                    mode |= FLUSH_ALL;
                    is_static_entry = attribute.value.s32;
                    if ( is_static_entry == SAI_FDB_FLUSH_ENTRY_TYPE_STATIC)
                    {
                        SWSS_LOG_ERROR(" Cannot Flush STATIC FDB_ENTRY OBJECTS");
                        return SAI_STATUS_FAILURE;
                    }
                }
                break;

            default:
                SWSS_LOG_ERROR(" Invalid Attributes for fdb entry flush OBJECT");
                return SAI_STATUS_FAILURE;
                break;
        }
    }
    /*
       Here three cases are handled, the FDB_ENTRY's are flushed based on the Attributes set,
       1. If Interface and Type(DYNAMIC is expected here), FLUSH by Interface.
       2. If Bridge_ID(VLAN_ID for .1q) and Type(DYNAMIC is expected here), FLUSH by Bridge ID.
       3. If only Type (DYNAMIC) is set then SONiC FLUSH ALL the dynamic entries.
       */
    SWSS_LOG_NOTICE("VPP_FDB_FLUSH mode is : %d [1,5: Interface, 2,6: Bridge, 3,4,7: Flush ALL, 0: INVALID]", mode);
    switch (mode)
    {
        case FLUSH_BY_INTERFACE:
        case FLUSH_BY_INTERFACE | FLUSH_ALL:/*flush by interface*/
            {
                auto br_port_attrs = m_objectHash.at(SAI_OBJECT_TYPE_BRIDGE_PORT).at(sai_serialize_object_id(br_port_id));
                auto meta = sai_metadata_get_attr_metadata(SAI_OBJECT_TYPE_BRIDGE_PORT, SAI_BRIDGE_PORT_ATTR_PORT_ID);
                auto bp_attr = br_port_attrs[meta->attridname];
                port_id = bp_attr->getAttr()->value.oid;
                sai_object_type_t obj_type = objectTypeQuery(port_id);

                if (obj_type != SAI_OBJECT_TYPE_PORT)
                {
                    SWSS_LOG_ERROR("SAI_BRIDGE_PORT_ATTR_PORT_ID=%s expected to be PORT but is: %s",
                            sai_serialize_object_id(port_id).c_str(),
                            sai_serialize_object_type(obj_type).c_str());
                    return SAI_STATUS_FAILURE;
                }
                std::string ifname = "";
                if (vpp_get_hwif_name(port_id, 0, ifname) == true)
                {
                    const char *hwif_name = ifname.c_str();
                    auto ret = l2fib_flush_int(hwif_name);
                    SWSS_LOG_NOTICE(" Flush by interface on hwif_name %s  Successful ret_val: %d", hwif_name, ret);
                }
                else
                {
                    SWSS_LOG_ERROR("Flush Interface FDB: Invalid ObjectID for the hwif on this bridge");

                    return SAI_STATUS_FAILURE;
                }
            }
            break;

        case FLUSH_BY_BD_ID:
        case FLUSH_BY_BD_ID | FLUSH_ALL: /*flush by bd_id/vlan id*/
            {
                auto ret = l2fib_flush_bd(bd_id);
                SWSS_LOG_NOTICE(" Flush on bd_id %d Successfull ret_val: %d",bd_id, ret);
            }
            break;

        case FLUSH_BY_INTERFACE | FLUSH_BY_BD_ID:
        case FLUSH_ALL:
        case FLUSH_BY_INTERFACE| FLUSH_BY_BD_ID| FLUSH_ALL: /*flush all*/
            {
                auto ret = l2fib_flush_all();
                SWSS_LOG_NOTICE(" Flush ALL fdb entry ret_val: %d", ret);
            }
            break;

        default:
            SWSS_LOG_ERROR(" Unable to find attrs for FDB_FLUSH %d", mode);
            return SAI_STATUS_FAILURE;
            break;

    }

    return SAI_STATUS_SUCCESS;
}

/*
 * vppPollFdb - Poll VPP l2fib and generate SAI FDB events
 *
 * This function dumps all L2 FIB entries from VPP bridge domains,
 * compares them with a local cache, and generates SAI_FDB_EVENT_LEARNED
 * or SAI_FDB_EVENT_AGED notifications for changes.
 *
 * VPP learns MACs in its own userspace dataplane (l2fib) but the SAI
 * virtual switch layer never sees these packets. This polling bridges
 * the gap, making VPP-learned MACs visible to SONiC's fdborch.
 */
void SwitchVpp::vppPollFdb()
{
    SWSS_LOG_ENTER();

    /* Build maps to resolve VPP sw_if_index → SAI bridge port info.
     *
     * For physical ports/LAGs: hwif_name → BridgePortInfo  (via vpp_get_swif_name)
     * For VxLAN tunnels:       sw_if_index → BridgePortInfo (via TunnelManager)
     *
     * Tunnel interfaces aren't in VPP's name hash (populated at sw_interface_dump
     * time, before tunnels are created), so we use sw_if_index directly. */

    struct BridgePortInfo {
        sai_object_id_t portId;       /* port/lag OID or tunnel OID for tunnels */
        sai_object_id_t bridgePortId;
        bool isTunnel;
        uint16_t vlanId;              /* set for tunnel BPs (from TunnelManager) */
    };

    std::map<std::string, BridgePortInfo> hwif_to_bp;    /* physical ports/LAGs */
    std::map<uint32_t, BridgePortInfo>    swif_to_bp;    /* tunnel bridge ports */

    auto &bpHash = m_objectHash.at(SAI_OBJECT_TYPE_BRIDGE_PORT);

    for (auto &kv : bpHash)
    {
        sai_object_id_t bpId;
        sai_deserialize_object_id(kv.first, bpId);

        /* Get bridge port type */
        sai_attribute_t attr;
        attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
        if (get(SAI_OBJECT_TYPE_BRIDGE_PORT, bpId, 1, &attr) != SAI_STATUS_SUCCESS)
            continue;

        auto bpType = (sai_bridge_port_type_t)attr.value.s32;

        if (bpType == SAI_BRIDGE_PORT_TYPE_TUNNEL)
        {
            /* Resolve tunnel bridge port via TunnelManager — use sw_if_index
             * directly since VPP's name hash doesn't know dynamic tunnels */
            attr.id = SAI_BRIDGE_PORT_ATTR_TUNNEL_ID;
            if (get(SAI_OBJECT_TYPE_BRIDGE_PORT, bpId, 1, &attr) != SAI_STATUS_SUCCESS)
                continue;

            sai_object_id_t tunnelOid = attr.value.oid;
            uint32_t sw_if_index = 0;
            uint16_t vlan_id = 0;
            if (!m_tunnel_mgr.getL2TunnelInfo(tunnelOid, sw_if_index, vlan_id))
                continue;

            BridgePortInfo info;
            info.portId = tunnelOid;
            info.bridgePortId = bpId;
            info.isTunnel = true;
            info.vlanId = vlan_id;
            swif_to_bp[sw_if_index] = info;
            continue;
        }

        /* Get the port/lag OID */
        attr.id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
        if (get(SAI_OBJECT_TYPE_BRIDGE_PORT, bpId, 1, &attr) != SAI_STATUS_SUCCESS)
            continue;

        sai_object_id_t portId = attr.value.oid;

        /* Resolve to VPP hw interface name */
        std::string hwif;
        if (!vpp_get_hwif_name(portId, 0, hwif))
            continue;

        BridgePortInfo info;
        info.portId = portId;
        info.bridgePortId = bpId;
        info.isTunnel = false;
        info.vlanId = 0;
        hwif_to_bp[hwif] = info;
    }

    if (hwif_to_bp.empty() && swif_to_bp.empty())
    {
        return; /* no bridge ports configured yet */
    }

    /* Build a set of all active BD IDs (VLAN IDs) from SAI VLANs */
    std::set<uint32_t> active_bds;

    auto &vlanHash = m_objectHash.at(SAI_OBJECT_TYPE_VLAN);
    for (auto &kv : vlanHash)
    {
        sai_object_id_t vlanOid;
        sai_deserialize_object_id(kv.first, vlanOid);

        sai_attribute_t attr;
        attr.id = SAI_VLAN_ATTR_VLAN_ID;
        if (get(SAI_OBJECT_TYPE_VLAN, vlanOid, 1, &attr) == SAI_STATUS_SUCCESS)
        {
            active_bds.insert(attr.value.u16);
        }
    }

    if (active_bds.empty())
    {
        return;
    }

    /* Dump l2fib for each active BD and build the new FDB map */
    std::map<VppFdbKey, VppFdbValue> new_fdb;

    auto dumpResult = std::make_unique<vpp_l2fib_dump_result_t>();

    for (uint32_t bd_id : active_bds)
    {
        memset(dumpResult.get(), 0, sizeof(vpp_l2fib_dump_result_t));

        int rc = l2fib_table_dump(bd_id, dumpResult.get());
        if (rc != 0)
        {
            SWSS_LOG_WARN("l2fib_table_dump failed for BD %u: %d", bd_id, rc);
            continue;
        }

        for (uint32_t i = 0; i < dumpResult->count; i++)
        {
            auto &e = dumpResult->entries[i];

            /* Skip BVI (gateway) and filter entries */
            if (e.bvi_mac || e.filter_mac)
                continue;

            /* Skip static entries — those were programmed by SONiC, not learned */
            if (e.static_mac)
                continue;

            VppFdbKey key;
            key.bd_id = e.bd_id;
            memcpy(key.mac, e.mac, 6);

            VppFdbValue val;
            val.sw_if_index = e.sw_if_index;
            val.static_mac = e.static_mac;
            val.bvi_mac = e.bvi_mac;

            new_fdb[key] = val;
        }
    }

    /* Diff: find newly learned MACs (in new_fdb but not in cache) */
    for (auto &kv : new_fdb)
    {
        auto it = m_vpp_fdb_cache.find(kv.first);
        if (it != m_vpp_fdb_cache.end() && it->second.sw_if_index == kv.second.sw_if_index)
            continue; /* already known, same port */

        /* New or moved MAC — generate SAI_FDB_EVENT_LEARNED */

        /* Resolve sw_if_index → bridge port info.
         * First check tunnel map (direct sw_if_index key), then fall back to
         * hwif name map for physical ports. */
        const BridgePortInfo *bp_info = nullptr;
        const char *port_name = nullptr;

        auto swif_it = swif_to_bp.find(kv.second.sw_if_index);
        if (swif_it != swif_to_bp.end())
        {
            /* Skip tunnel-learned MACs — remote MACs should come via EVPN
             * control plane (BGP Type-2 → fdbsyncd), not SAI FDB events.
             * VPP learns them on the data plane for local forwarding only. */
            SWSS_LOG_DEBUG("vppPollFdb: skipping tunnel-learned MAC sw_if_index %u", kv.second.sw_if_index);
            continue;
        }
        else
        {
            const char *hwif = vpp_get_swif_name(kv.second.sw_if_index);
            if (!hwif)
            {
                SWSS_LOG_WARN("vppPollFdb: cannot resolve sw_if_index %u", kv.second.sw_if_index);
                continue;
            }
            port_name = hwif;

            auto bp_it = hwif_to_bp.find(std::string(hwif));
            if (bp_it == hwif_to_bp.end())
            {
                SWSS_LOG_DEBUG("vppPollFdb: hwif %s not mapped to bridge port, skipping", hwif);
                continue;
            }
            bp_info = &bp_it->second;
        }

        /* Find the VLAN OID for this BD */
        sai_object_id_t bv_id = SAI_NULL_OBJECT_ID;
        for (auto &vkv : vlanHash)
        {
            sai_object_id_t vlanOid;
            sai_deserialize_object_id(vkv.first, vlanOid);
            sai_attribute_t attr;
            attr.id = SAI_VLAN_ATTR_VLAN_ID;
            if (get(SAI_OBJECT_TYPE_VLAN, vlanOid, 1, &attr) == SAI_STATUS_SUCCESS)
            {
                if (attr.value.u16 == kv.first.bd_id)
                {
                    bv_id = vlanOid;
                    break;
                }
            }
        }

        if (bv_id == SAI_NULL_OBJECT_ID)
        {
            SWSS_LOG_WARN("vppPollFdb: cannot find VLAN OID for BD %u", kv.first.bd_id);
            continue;
        }

        /* Build FdbInfo and generate event */
        FdbInfo fi;
        fi.setPortId(bp_info->portId);
        fi.setVlanId((sai_vlan_id_t)kv.first.bd_id);
        fi.m_bridgePortId = bp_info->bridgePortId;
        fi.m_fdbEntry.switch_id = m_switch_id;
        fi.m_fdbEntry.bv_id = bv_id;
        memcpy(fi.m_fdbEntry.mac_address, kv.first.mac, sizeof(sai_mac_t));
        fi.setTimestamp((uint32_t)time(NULL));

        m_fdb_info_set.insert(fi);

        SWSS_LOG_NOTICE("vppPollFdb: LEARNED mac=%02x:%02x:%02x:%02x:%02x:%02x bd=%u port=%s",
                kv.first.mac[0], kv.first.mac[1], kv.first.mac[2],
                kv.first.mac[3], kv.first.mac[4], kv.first.mac[5],
                kv.first.bd_id, port_name);

        processFdbInfo(fi, SAI_FDB_EVENT_LEARNED);
    }

    /* Diff: find aged MACs (in cache but not in new_fdb) */
    for (auto &kv : m_vpp_fdb_cache)
    {
        if (new_fdb.find(kv.first) != new_fdb.end())
            continue; /* still present */

        /* MAC disappeared from VPP — generate SAI_FDB_EVENT_AGED */

        /* Skip tunnel-learned MACs (same as LEARNED path) */
        auto swif_it = swif_to_bp.find(kv.second.sw_if_index);
        if (swif_it != swif_to_bp.end())
            continue;

        /* Resolve sw_if_index → bridge port info (physical ports only) */
        sai_object_id_t portId = SAI_NULL_OBJECT_ID;
        sai_object_id_t bpId = SAI_NULL_OBJECT_ID;

        {
            const char *hwif = vpp_get_swif_name(kv.second.sw_if_index);
            if (hwif)
            {
                auto bp_it = hwif_to_bp.find(std::string(hwif));
                if (bp_it != hwif_to_bp.end())
                {
                    portId = bp_it->second.portId;
                    bpId = bp_it->second.bridgePortId;
                }
            }
        }

        /* Find VLAN OID */
        sai_object_id_t bv_id = SAI_NULL_OBJECT_ID;
        for (auto &vkv : vlanHash)
        {
            sai_object_id_t vlanOid;
            sai_deserialize_object_id(vkv.first, vlanOid);
            sai_attribute_t attr;
            attr.id = SAI_VLAN_ATTR_VLAN_ID;
            if (get(SAI_OBJECT_TYPE_VLAN, vlanOid, 1, &attr) == SAI_STATUS_SUCCESS)
            {
                if (attr.value.u16 == kv.first.bd_id)
                {
                    bv_id = vlanOid;
                    break;
                }
            }
        }

        if (bv_id == SAI_NULL_OBJECT_ID || portId == SAI_NULL_OBJECT_ID)
        {
            SWSS_LOG_DEBUG("vppPollFdb: cannot resolve aged MAC bd=%u, skipping event", kv.first.bd_id);
            continue;
        }

        FdbInfo fi;
        fi.setPortId(portId);
        fi.setVlanId((sai_vlan_id_t)kv.first.bd_id);
        fi.m_bridgePortId = bpId;
        fi.m_fdbEntry.switch_id = m_switch_id;
        fi.m_fdbEntry.bv_id = bv_id;
        memcpy(fi.m_fdbEntry.mac_address, kv.first.mac, sizeof(sai_mac_t));

        auto sit = m_fdb_info_set.find(fi);
        if (sit != m_fdb_info_set.end())
        {
            m_fdb_info_set.erase(sit);
        }

        SWSS_LOG_NOTICE("vppPollFdb: AGED mac=%02x:%02x:%02x:%02x:%02x:%02x bd=%u",
                kv.first.mac[0], kv.first.mac[1], kv.first.mac[2],
                kv.first.mac[3], kv.first.mac[4], kv.first.mac[5],
                kv.first.bd_id);

        processFdbInfo(fi, SAI_FDB_EVENT_AGED);
    }

    /* Update the cache */
    m_vpp_fdb_cache = new_fdb;
}

/*
 * vppProcessL2MacEvent - Process a VPP L2 MAC learn/age/move event
 *
 * Called from the events thread when VPP fires an l2_macs_event callback.
 * Maps sw_if_index to SAI bridge ports and generates SAI FDB events.
 *
 * This is the event-driven path — lower latency than polling. The poll
 * fallback (vppPollFdb) still runs periodically to catch stragglers.
 */
void SwitchVpp::vppProcessL2MacEvent(
        _In_ const vpp_l2_mac_event_t *event)
{
    SWSS_LOG_ENTER();

    if (!event || event->n_macs == 0)
        return;

    /* Build maps to resolve sw_if_index → bridge port info (same approach as vppPollFdb) */
    struct BridgePortInfo {
        sai_object_id_t portId;
        sai_object_id_t bridgePortId;
        bool isTunnel;
        uint16_t vlanId;              /* set for tunnel BPs (from TunnelManager) */
    };

    std::map<std::string, BridgePortInfo> hwif_to_bp;    /* physical ports/LAGs */
    std::map<uint32_t, BridgePortInfo>    swif_to_bp;    /* tunnel bridge ports */

    auto bpIt = m_objectHash.find(SAI_OBJECT_TYPE_BRIDGE_PORT);
    if (bpIt == m_objectHash.end())
        return;

    auto &bpHash = bpIt->second;

    for (auto &kv : bpHash)
    {
        sai_object_id_t bpId;
        sai_deserialize_object_id(kv.first, bpId);

        sai_attribute_t attr;
        attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
        if (get(SAI_OBJECT_TYPE_BRIDGE_PORT, bpId, 1, &attr) != SAI_STATUS_SUCCESS)
            continue;

        auto bpType = (sai_bridge_port_type_t)attr.value.s32;

        if (bpType == SAI_BRIDGE_PORT_TYPE_TUNNEL)
        {
            attr.id = SAI_BRIDGE_PORT_ATTR_TUNNEL_ID;
            if (get(SAI_OBJECT_TYPE_BRIDGE_PORT, bpId, 1, &attr) != SAI_STATUS_SUCCESS)
                continue;

            sai_object_id_t tunnelOid = attr.value.oid;
            uint32_t sw_if_index = 0;
            uint16_t vlan_id = 0;
            if (!m_tunnel_mgr.getL2TunnelInfo(tunnelOid, sw_if_index, vlan_id))
                continue;

            BridgePortInfo info;
            info.portId = tunnelOid;
            info.bridgePortId = bpId;
            info.isTunnel = true;
            info.vlanId = vlan_id;
            swif_to_bp[sw_if_index] = info;
            continue;
        }

        attr.id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
        if (get(SAI_OBJECT_TYPE_BRIDGE_PORT, bpId, 1, &attr) != SAI_STATUS_SUCCESS)
            continue;

        sai_object_id_t portId = attr.value.oid;
        std::string hwif;
        if (!vpp_get_hwif_name(portId, 0, hwif))
            continue;

        BridgePortInfo info;
        info.portId = portId;
        info.bridgePortId = bpId;
        info.isTunnel = false;
        info.vlanId = 0;
        hwif_to_bp[hwif] = info;
    }

    if (hwif_to_bp.empty() && swif_to_bp.empty())
        return;

    /* Build VLAN ID → VLAN OID map */
    std::map<uint16_t, sai_object_id_t> vlanid_to_oid;

    auto vlanIt = m_objectHash.find(SAI_OBJECT_TYPE_VLAN);
    if (vlanIt != m_objectHash.end())
    {
        for (auto &kv : vlanIt->second)
        {
            sai_object_id_t vlanOid;
            sai_deserialize_object_id(kv.first, vlanOid);
            sai_attribute_t attr;
            attr.id = SAI_VLAN_ATTR_VLAN_ID;
            if (get(SAI_OBJECT_TYPE_VLAN, vlanOid, 1, &attr) == SAI_STATUS_SUCCESS)
            {
                vlanid_to_oid[attr.value.u16] = vlanOid;
            }
        }
    }

    /* Process each MAC entry in the event */
    for (uint32_t i = 0; i < event->n_macs; i++)
    {
        auto &entry = event->entries[i];

        /* Resolve sw_if_index → bridge port info.
         * Check tunnel map first (direct sw_if_index), then hwif name map. */
        const BridgePortInfo *bp_info = nullptr;
        const char *port_name = nullptr;

        auto swif_it = swif_to_bp.find(entry.sw_if_index);
        if (swif_it != swif_to_bp.end())
        {
            /* Skip tunnel-learned MACs — remote MACs should come via EVPN
             * control plane (BGP Type-2 → fdbsyncd), not SAI FDB events.
             * VPP learns them on the data plane for local forwarding only. */
            SWSS_LOG_DEBUG("vppProcessL2MacEvent: skipping tunnel-learned MAC sw_if_index %u", entry.sw_if_index);
            continue;
        }
        else
        {
            const char *hwif = vpp_get_swif_name(entry.sw_if_index);
            if (!hwif)
            {
                SWSS_LOG_DEBUG("vppProcessL2MacEvent: cannot resolve sw_if_index %u", entry.sw_if_index);
                continue;
            }
            port_name = hwif;

            auto bp_it = hwif_to_bp.find(std::string(hwif));
            if (bp_it == hwif_to_bp.end())
            {
                SWSS_LOG_DEBUG("vppProcessL2MacEvent: hwif %s not mapped to bridge port", hwif);
                continue;
            }
            bp_info = &bp_it->second;
        }

        /* Resolve VLAN for this bridge port.
         * Tunnel BPs aren't in VLAN_MEMBER — use vlanId from TunnelManager.
         * Physical port BPs are found via VLAN_MEMBER scan. */
        sai_object_id_t bv_id = SAI_NULL_OBJECT_ID;
        sai_vlan_id_t vlan_id = 0;

        if (bp_info->isTunnel && bp_info->vlanId != 0)
        {
            vlan_id = bp_info->vlanId;
            /* Look up VLAN OID from vlanid_to_oid map */
            auto vit = vlanid_to_oid.find(vlan_id);
            if (vit != vlanid_to_oid.end())
                bv_id = vit->second;
        }
        else
        {
            /* Check VLAN members to find which VLAN this bridge port belongs to */
            auto vmIt = m_objectHash.find(SAI_OBJECT_TYPE_VLAN_MEMBER);
            if (vmIt != m_objectHash.end())
            {
                for (auto &vmkv : vmIt->second)
                {
                    sai_object_id_t vmId;
                    sai_deserialize_object_id(vmkv.first, vmId);

                    sai_attribute_t attr;
                    attr.id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
                    if (get(SAI_OBJECT_TYPE_VLAN_MEMBER, vmId, 1, &attr) != SAI_STATUS_SUCCESS)
                        continue;

                    if (attr.value.oid != bp_info->bridgePortId)
                        continue;

                    /* Found it — get the VLAN */
                    attr.id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
                    if (get(SAI_OBJECT_TYPE_VLAN_MEMBER, vmId, 1, &attr) == SAI_STATUS_SUCCESS)
                    {
                        sai_object_id_t vlanOid = attr.value.oid;
                        sai_attribute_t vattr;
                        vattr.id = SAI_VLAN_ATTR_VLAN_ID;
                        if (get(SAI_OBJECT_TYPE_VLAN, vlanOid, 1, &vattr) == SAI_STATUS_SUCCESS)
                        {
                            vlan_id = vattr.value.u16;
                            bv_id = vlanOid;
                        }
                    }
                    break;
                }
            }
        }

        if (bv_id == SAI_NULL_OBJECT_ID)
        {
            SWSS_LOG_DEBUG("vppProcessL2MacEvent: cannot find VLAN for bridge port %s",
                    sai_serialize_object_id(bp_info->bridgePortId).c_str());
            continue;
        }

        /* Map VPP action to SAI FDB event */
        sai_fdb_event_t fdb_event;
        switch (entry.action)
        {
            case VPP_L2_MAC_EVENT_ACTION_ADD:
            case VPP_L2_MAC_EVENT_ACTION_MOVE:
                fdb_event = SAI_FDB_EVENT_LEARNED;
                break;
            case VPP_L2_MAC_EVENT_ACTION_DELETE:
                fdb_event = SAI_FDB_EVENT_AGED;
                break;
            default:
                SWSS_LOG_WARN("vppProcessL2MacEvent: unknown action %u", entry.action);
                continue;
        }

        /* Build FdbInfo and generate event */
        FdbInfo fi;
        fi.setPortId(bp_info->portId);
        fi.setVlanId(vlan_id);
        fi.m_bridgePortId = bp_info->bridgePortId;
        fi.m_fdbEntry.switch_id = m_switch_id;
        fi.m_fdbEntry.bv_id = bv_id;
        memcpy(fi.m_fdbEntry.mac_address, entry.mac, sizeof(sai_mac_t));
        fi.setTimestamp((uint32_t)time(NULL));

        if (fdb_event == SAI_FDB_EVENT_LEARNED)
        {
            m_fdb_info_set.insert(fi);
        }
        else if (fdb_event == SAI_FDB_EVENT_AGED)
        {
            auto sit = m_fdb_info_set.find(fi);
            if (sit != m_fdb_info_set.end())
                m_fdb_info_set.erase(sit);
        }

        /* Also update the poll cache so polling doesn't re-fire */
        VppFdbKey key;
        key.bd_id = vlan_id; /* BD ID == VLAN ID in our mapping */
        memcpy(key.mac, entry.mac, 6);

        if (fdb_event == SAI_FDB_EVENT_LEARNED)
        {
            VppFdbValue val;
            val.sw_if_index = entry.sw_if_index;
            val.static_mac = false;
            val.bvi_mac = false;
            m_vpp_fdb_cache[key] = val;
        }
        else
        {
            m_vpp_fdb_cache.erase(key);
        }

        SWSS_LOG_NOTICE("vppProcessL2MacEvent: %s mac=%02x:%02x:%02x:%02x:%02x:%02x "
                "vlan=%u port=%s action=%u",
                (fdb_event == SAI_FDB_EVENT_LEARNED) ? "LEARNED" : "AGED",
                entry.mac[0], entry.mac[1], entry.mac[2],
                entry.mac[3], entry.mac[4], entry.mac[5],
                vlan_id, port_name, entry.action);

        processFdbInfo(fi, fdb_event);
    }
}
