/*
 * SwitchVppEsProtect.cpp - ES Protect virtual bridge port for EVPN MH v2.0
 *
 * When a LAG (PortChannel) with ES attributes is added to a bridge domain,
 * we create a VPP es-protect virtual interface (via vppctl CLI) and add
 * that to the BD instead of the raw BondEthernet. This gives us:
 *   - Unicast failover: primary (local bond) → standby (VxLAN tunnel ECMP)
 *   - BUM: primary only (skip if down, peer T1 delivers via VxLAN)
 *
 * Copyright (c) 2026 Microsoft Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

#include "SwitchVpp.h"

#include "swss/logger.h"

#include <cstdio>
#include <string>
#include <sstream>
#include <map>
#include <vector>

using namespace saivs;

/*
 * ES Protect state tracking.
 */
struct EsProtectEntry {
    uint32_t bond_sw_if_index;
    std::string bond_ifname;
    std::string es_protect_ifname;
    uint32_t bd_id;
    std::vector<std::string> standby_vteps;
};

/* Keyed by bond interface name (e.g. "BondEthernet0") */
static std::map<std::string, EsProtectEntry> s_es_protect_entries;

/*
 * Execute a vppctl command and return the output.
 */
static int
vppctl_exec(const std::string &cmd, std::string &output)
{
    std::string full_cmd = "vppctl " + cmd + " 2>&1";
    SWSS_LOG_NOTICE("ES-Protect vppctl: %s", full_cmd.c_str());

    FILE *fp = popen(full_cmd.c_str(), "r");
    if (!fp) {
        SWSS_LOG_ERROR("ES-Protect: popen failed for: %s", full_cmd.c_str());
        return -1;
    }

    char buf[512];
    output.clear();
    while (fgets(buf, sizeof(buf), fp))
        output += buf;

    int rc = pclose(fp);
    if (rc != 0)
        SWSS_LOG_WARN("ES-Protect vppctl rc=%d output: %s", rc, output.c_str());
    else
        SWSS_LOG_NOTICE("ES-Protect vppctl ok: %s", output.c_str());
    return rc;
}

/*
 * Check if a PortChannel has ES attributes by querying ConfigDB.
 * Bond interface names in VPP are "BondEthernetN" where N corresponds
 * to PortChannelN. We map back to PortChannel name and check ConfigDB.
 */
static bool
isEsProtectedBond(const std::string &bond_ifname)
{
    /* Extract bond ID: "BondEthernet0" → "0" → "PortChannel0" */
    std::string bond_id_str;
    if (bond_ifname.find("BondEthernet") == 0) {
        bond_id_str = bond_ifname.substr(12);
    } else {
        return false;
    }

    std::string pc_name = "PortChannel" + bond_id_str;

    /* Check ConfigDB via redis-cli (PoC simplicity) */
    std::string cmd = "redis-cli -n 4 HGET 'PORTCHANNEL|" + pc_name + "' evpn_es_id 2>/dev/null";
    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) return false;

    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), fp))
        result += buf;
    pclose(fp);

    /* Trim whitespace */
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();

    if (result.empty() || result == "(nil)") {
        return false;
    }

    SWSS_LOG_NOTICE("ES-Protect: %s (%s) has ES ID: %s",
                    bond_ifname.c_str(), pc_name.c_str(), result.c_str());
    return true;
}

/*
 * Create an es-protect interface for a bond being added to a BD.
 * Returns the es-protect interface name to add to the BD instead.
 */
sai_status_t
SwitchVpp::createEsProtectForBond(const std::string &bond_ifname,
                                   uint32_t bd_id,
                                   std::string &ep_ifname_out)
{
    SWSS_LOG_ENTER();

    /* Check if already created */
    auto it = s_es_protect_entries.find(bond_ifname);
    if (it != s_es_protect_entries.end()) {
        ep_ifname_out = it->second.es_protect_ifname;
        SWSS_LOG_NOTICE("ES-Protect: reusing %s for %s",
                        ep_ifname_out.c_str(), bond_ifname.c_str());
        return SAI_STATUS_SUCCESS;
    }

    /* Create es-protect interface via vppctl */
    std::string output;
    std::string cmd = "create es-protect primary " + bond_ifname;
    if (vppctl_exec(cmd, output) != 0) {
        SWSS_LOG_ERROR("ES-Protect: failed to create for %s", bond_ifname.c_str());
        return SAI_STATUS_FAILURE;
    }

    /* Parse the interface name from output like "Created es-protect interface: es-protect0" */
    auto pos = output.find("es-protect");
    if (pos != std::string::npos) {
        /* Find the last occurrence (the actual interface name, not "es-protect interface:") */
        auto last = output.rfind("es-protect");
        auto end = output.find_first_of(" \n\r", last);
        if (end == std::string::npos) end = output.size();
        ep_ifname_out = output.substr(last, end - last);
    } else {
        SWSS_LOG_ERROR("ES-Protect: unexpected output: %s", output.c_str());
        return SAI_STATUS_FAILURE;
    }

    /*
     * Refresh VPP interface name→sw_if_index cache.
     * The es-protect interface was created via vppctl CLI (popen), which
     * bypasses the VPP C API. The SAI xlate layer's local cache doesn't
     * know about it, so set_sw_interface_l2_bridge() would fail to resolve
     * the name. Refreshing the cache picks up the new interface.
     */
    refresh_interfaces_list();

    /* Record state */
    EsProtectEntry entry;
    entry.bond_ifname = bond_ifname;
    entry.es_protect_ifname = ep_ifname_out;
    entry.bd_id = bd_id;
    s_es_protect_entries[bond_ifname] = entry;

    SWSS_LOG_NOTICE("ES-Protect: created %s for %s in BD %u",
                    ep_ifname_out.c_str(), bond_ifname.c_str(), bd_id);

    /*
     * Set NO_FLOOD on the bond interface. The bond stays in the BD for
     * ingress (RX + MAC learning), but l2-flood skips it for TX — the
     * es-protect interface handles all egress to the bond via its TX node.
     * This prevents duplicate BUM frames.
     */
    {
        std::string discard;
        vppctl_exec("es-protect set-no-flood " + bond_ifname, discard);
    }

    /*
     * Add the bond to the BD as a normal member (for RX).
     * The NO_FLOOD flag was set above, so it won't receive flooded TX.
     */
    set_sw_interface_l2_bridge(bond_ifname.c_str(), bd_id, true, VPP_API_PORT_TYPE_NORMAL);

    /*
     * Auto-configure standby VxLAN tunnel from ConfigDB peer_vteps.
     * This makes the failover path available at boot without manual steps.
     */
    {
        std::string pc_name = "PortChannel" + bond_ifname.substr(12); /* BondEthernetN → PortChannelN */
        std::string vtep_cmd = "redis-cli -n 4 HGET 'PORTCHANNEL|" + pc_name + "' peer_vteps 2>/dev/null";
        FILE *fp = popen(vtep_cmd.c_str(), "r");
        if (fp) {
            char buf[256];
            std::string vteps;
            while (fgets(buf, sizeof(buf), fp))
                vteps += buf;
            pclose(fp);
            while (!vteps.empty() && (vteps.back() == '\n' || vteps.back() == '\r'))
                vteps.pop_back();
            if (!vteps.empty() && vteps != "(nil)") {
                SWSS_LOG_NOTICE("ES-Protect: auto-configuring standby from peer_vteps: %s", vteps.c_str());
                updateEsProtectStandby(bond_ifname, vteps);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

/*
 * Update standby ECMP list for an ES-protect interface.
 * remote_vteps is comma-separated list of VTEP IPs.
 */
sai_status_t
SwitchVpp::updateEsProtectStandby(const std::string &bond_ifname,
                                   const std::string &remote_vteps_csv)
{
    SWSS_LOG_ENTER();

    auto it = s_es_protect_entries.find(bond_ifname);
    if (it == s_es_protect_entries.end()) {
        SWSS_LOG_NOTICE("ES-Protect: no entry for %s", bond_ifname.c_str());
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    auto &entry = it->second;

    /* Parse VTEP IPs */
    std::vector<std::string> vteps;
    std::istringstream iss(remote_vteps_csv);
    std::string vtep;
    while (std::getline(iss, vtep, ',')) {
        while (!vtep.empty() && vtep[0] == ' ') vtep.erase(0, 1);
        if (!vtep.empty())
            vteps.push_back(vtep);
    }

    /* Remove old standby interfaces — clear all via CLI */
    if (!entry.standby_vteps.empty()) {
        std::string cmd = "set es-protect " + entry.es_protect_ifname + " standby clear";
        std::string discard;
        vppctl_exec(cmd, discard);
    }

    /* Add new standby interfaces by finding VxLAN tunnels */
    entry.standby_vteps.clear();
    for (const auto &vtep_ip : vteps) {
        /* Find the VxLAN tunnel interface for this remote VTEP IP
         * VPP names them vxlan_tunnel0, vxlan_tunnel1, etc. */
        std::string show_out;
        vppctl_exec("show vxlan tunnel", show_out);

        /* Parse: look for line containing "dst <vtep_ip>"
         * VPP format: [N] instance N src X dst Y ... sw-if-idx I ...
         * Extract instance number and construct vxlan_tunnelN */
        std::string tun_name;
        std::string dst_match = "dst " + vtep_ip;
        std::istringstream lines(show_out);
        std::string line;
        while (std::getline(lines, line)) {
            if (line.find(dst_match) != std::string::npos) {
                /* Extract instance number from "[N] instance N" */
                auto inst_pos = line.find("instance ");
                if (inst_pos != std::string::npos) {
                    inst_pos += 9; /* skip "instance " */
                    auto end_pos = line.find(' ', inst_pos);
                    std::string inst = line.substr(inst_pos,
                        end_pos != std::string::npos ? end_pos - inst_pos : std::string::npos);
                    tun_name = "vxlan_tunnel" + inst;
                }
                break;
            }
        }

        if (tun_name.empty()) {
            SWSS_LOG_WARN("ES-Protect: no VxLAN tunnel for VTEP %s", vtep_ip.c_str());
            continue;
        }

        std::string output;
        std::string cmd = "set es-protect " + entry.es_protect_ifname +
                          " standby add " + tun_name;
        vppctl_exec(cmd, output);
        entry.standby_vteps.push_back(vtep_ip);
    }

    SWSS_LOG_NOTICE("ES-Protect: updated %s standby: %zu VTEPs",
                    entry.es_protect_ifname.c_str(), entry.standby_vteps.size());
    return SAI_STATUS_SUCCESS;
}

/*
 * Check if a bond interface name has ES protection.
 * Used by vpp_create_vlan_member to decide whether to create es-protect.
 */
bool
SwitchVpp::shouldCreateEsProtect(const std::string &hwifname)
{
    return isEsProtectedBond(std::string(hwifname));
}

/*
 * Retry standby configuration for es-protect entries that have empty standby
 * lists. Called from VxLAN tunnel creation path — at boot, es-protect is
 * created before the tunnel exists, so the initial standby config fails.
 * When a tunnel is subsequently created, this retries and succeeds.
 */
void
SwitchVpp::retryPendingEsProtectStandby()
{
    SWSS_LOG_ENTER();

    for (auto &kv : s_es_protect_entries) {
        auto &entry = kv.second;
        if (!entry.standby_vteps.empty())
            continue; /* already configured */

        /* Re-read peer_vteps from ConfigDB */
        std::string pc_name = "PortChannel" + entry.bond_ifname.substr(12);
        std::string cmd = "redis-cli -n 4 HGET 'PORTCHANNEL|" + pc_name + "' peer_vteps 2>/dev/null";
        FILE *fp = popen(cmd.c_str(), "r");
        if (!fp) continue;

        char buf[256];
        std::string vteps;
        while (fgets(buf, sizeof(buf), fp))
            vteps += buf;
        pclose(fp);
        while (!vteps.empty() && (vteps.back() == '\n' || vteps.back() == '\r'))
            vteps.pop_back();

        if (vteps.empty() || vteps == "(nil)")
            continue;

        SWSS_LOG_NOTICE("ES-Protect: retrying standby for %s from peer_vteps: %s",
                        entry.es_protect_ifname.c_str(), vteps.c_str());
        updateEsProtectStandby(entry.bond_ifname, vteps);
    }
}
