/*
 * Copyright (C) 2019-2023 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "context.h"
#include "event.h"
#include "timer.h"
#include "upf-sm.h"

#include "pfcp-path.h"
#include "n4-handler.h"

#include <inttypes.h>

static void pfcp_restoration(ogs_pfcp_node_t *node);
static void node_timeout(ogs_pfcp_xact_t *xact, void *data);

void upf_pfcp_state_initial(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;

    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    node->t_no_heartbeat = ogs_timer_add(ogs_app()->timer_mgr,
            upf_timer_no_heartbeat, node);
    ogs_assert(node->t_no_heartbeat);

    OGS_FSM_TRAN(s, &upf_pfcp_state_will_associate);
}

void upf_pfcp_state_final(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    ogs_timer_delete(node->t_no_heartbeat);
}

void upf_pfcp_state_will_associate(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        if (node->t_association) {
            ogs_timer_start(node->t_association,
                ogs_local_conf()->time.message.pfcp.association_interval);

            ogs_pfcp_up_send_association_setup_request(node, node_timeout);
        }
        break;

    case OGS_FSM_EXIT_SIG:
        if (node->t_association) {
            ogs_timer_stop(node->t_association);
        }
        break;

    case UPF_EVT_N4_TIMER:
        switch(e->timer_id) {
        case UPF_TIMER_ASSOCIATION:
            ogs_warn("Retry association with peer failed %s",
                    ogs_sockaddr_to_string_static(node->addr_list));

            ogs_assert(node->t_association);
            ogs_timer_start(node->t_association,
                ogs_local_conf()->time.message.pfcp.association_interval);

            ogs_pfcp_up_send_association_setup_request(node, node_timeout);
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    upf_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case UPF_EVT_N4_MESSAGE:
        message = e->pfcp_message;
        ogs_assert(message);
        xact = ogs_pfcp_xact_find_by_id(e->pfcp_xact_id);
        ogs_assert(xact);

        switch (message->h.type) {
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_request(node, xact,
                    &message->pfcp_heartbeat_request));
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_response(node, xact,
                    &message->pfcp_heartbeat_response));
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            ogs_pfcp_up_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);
            OGS_FSM_TRAN(s, upf_pfcp_state_associated);
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            ogs_pfcp_up_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);
            OGS_FSM_TRAN(s, upf_pfcp_state_associated);
            break;
        default:
            ogs_warn("cannot handle PFCP message type[%d]",
                    message->h.type);
            break;
        }
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_pfcp_state_associated(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_pfcp_node_t *node = NULL;
    ogs_pfcp_xact_t *xact = NULL;
    ogs_pfcp_message_t *message = NULL;

    upf_sess_t *sess = NULL;

    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    node = e->pfcp_node;
    ogs_assert(node);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        ogs_info("PFCP associated %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        ogs_timer_start(node->t_no_heartbeat,
                ogs_local_conf()->time.message.pfcp.no_heartbeat_duration);
        ogs_assert(OGS_OK ==
            ogs_pfcp_send_heartbeat_request(node, node_timeout));

        if (node->restoration_required == true) {
            pfcp_restoration(node);
            node->restoration_required = false;
            ogs_error("PFCP restoration");
        }

        upf_metrics_inst_global_inc(UPF_METR_GLOB_GAUGE_PFCP_PEERS_ACTIVE);
        break;
    case OGS_FSM_EXIT_SIG:
        ogs_info("PFCP de-associated %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        ogs_timer_stop(node->t_no_heartbeat);

        upf_metrics_inst_global_dec(UPF_METR_GLOB_GAUGE_PFCP_PEERS_ACTIVE);
        break;
    case UPF_EVT_N4_MESSAGE:
        message = e->pfcp_message;
        ogs_assert(message);
        xact = ogs_pfcp_xact_find_by_id(e->pfcp_xact_id);
        ogs_assert(xact);

        if (message->h.seid_presence && message->h.seid != 0)
            sess = upf_sess_find_by_upf_n4_seid(message->h.seid);

        switch (message->h.type) {
        case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_request(node, xact,
                    &message->pfcp_heartbeat_request));
            if (node->restoration_required == true) {
                if (node->t_association) {
        /*
         * node->t_association that the PFCP entity attempts an association.
         *
         * In this case, even if Remote PFCP entity is restarted,
         * PFCP restoration must be performed after PFCP association.
         *
         * Otherwise, Session related PFCP cannot be initiated
         * because the peer PFCP entity is in a de-associated state.
         */
                    OGS_FSM_TRAN(s, upf_pfcp_state_will_associate);
                } else {

        /*
         * If the peer PFCP entity is performing the association,
         * Restoration can be performed immediately.
         */
                    pfcp_restoration(node);
                    node->restoration_required = false;
                    ogs_error("PFCP restoration");
                }
            }
            break;
        case OGS_PFCP_HEARTBEAT_RESPONSE_TYPE:
            ogs_expect(true ==
                ogs_pfcp_handle_heartbeat_response(node, xact,
                    &message->pfcp_heartbeat_response));
            if (node->restoration_required == true) {
        /*
         * node->t_association that the PFCP entity attempts an association.
         *
         * In this case, even if Remote PFCP entity is restarted,
         * PFCP restoration must be performed after PFCP association.
         *
         * Otherwise, Session related PFCP cannot be initiated
         * because the peer PFCP entity is in a de-associated state.
         */
                if (node->t_association) {
                    OGS_FSM_TRAN(s, upf_pfcp_state_will_associate);
                } else {
        /*
         * If the peer PFCP entity is performing the association,
         * Restoration can be performed immediately.
         */
                    pfcp_restoration(node);
                    node->restoration_required = false;
                    ogs_error("PFCP restoration");
                }
            }
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
            ogs_warn("PFCP[REQ] has already been associated %s",
                    ogs_sockaddr_to_string_static(node->addr_list));
            ogs_pfcp_up_handle_association_setup_request(node, xact,
                    &message->pfcp_association_setup_request);
            break;
        case OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE:
            ogs_warn("PFCP[RSP] has already been associated %s",
                    ogs_sockaddr_to_string_static(node->addr_list));
            ogs_pfcp_up_handle_association_setup_response(node, xact,
                    &message->pfcp_association_setup_response);
            break;
        case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
            sess = upf_sess_add_by_message(message);
            if (sess)
                OGS_SETUP_PFCP_NODE(sess, node);

            upf_n4_handle_session_establishment_request(
                sess, xact, &message->pfcp_session_establishment_request);

            // 打印UE IP地址信息 -0513-
            if (sess) {
                char buf1[OGS_ADDRSTRLEN];
                char buf2[OGS_ADDRSTRLEN];
                ogs_info("UE Session Established - IPv4: %s, IPv6: %s",
                    sess->ipv4 ? OGS_INET_NTOP(&sess->ipv4->addr, buf1) : "N/A",
                    sess->ipv6 ? OGS_INET6_NTOP(&sess->ipv6->addr, buf2) : "N/A");
            }

            break;

        case OGS_PFCP_SESSION_MODIFICATION_REQUEST_TYPE:  
            // 调试
            // 打印整个 PFCP 消息基本头信息
            ogs_info("PFCP MODIFICATION REQUEST received:");
            ogs_info("  Type: %d", message->h.type);
            ogs_info("  SEID: 0x%lx", (unsigned long)message->h.seid);
            ogs_info("  Length: %d", ntohs(message->h.length));
            ogs_info("  SQN: %d", message->h.sqn_only);
            
            // remove 处理片段
            bool remove_requested = false;
            ogs_pfcp_session_modification_request_t *req = &message->pfcp_session_modification_request;
            // 检查 remove_pdr IE（假设数组长度为 16）
            for (int i = 0; i < 16; i++){
                if (req->remove_pdr[i].presence){
                    ogs_info("Remove PDR[%d] present, pdr_id: %u", i, *(uint16_t *)&(req->remove_pdr[i].pdr_id));
                    remove_requested = true;
                    break;
                }
            }
            // 检查 remove_qer IE（假设数组长度为 OGS_MAX_NUM_OF_QER）
            if (!remove_requested){
                for (int i = 0; i < OGS_MAX_NUM_OF_QER; i++){
                    if (req->remove_qer[i].presence){
                        ogs_info("Remove QER[%d] present, qer_id: %u", i, *(uint32_t *)&(req->remove_qer[i].qer_id));
                        remove_requested = true;
                        break;
                    }
                }
            }
            // 如果检测到 Remove 请求，则清除下边增加的特别的TC规则，让整个PDU session保持默认MBR
            /* 先放到下边测试
            if (remove_requested){
                const char *interface = "ogstun";
                char tc_cmd[512];
                ogs_info("Detected remove IE in PFCP message, clearing the specific tc rules...");

                // 删除特别速率（下边用于提升的速率）：filter prio 1 和 class 1:10
                snprintf(tc_cmd, sizeof(tc_cmd), "sudo tc filter del dev %s protocol ip parent 1: prio 1", interface);
                system(tc_cmd);
                snprintf(tc_cmd, sizeof(tc_cmd), "sudo tc class del dev %s classid 1:10", interface);
                system(tc_cmd);

                ogs_info("✅ The specific tc rules have been cleared on interface %s", interface);
                // 2) 继续处理 PFCP 请求 -> 产生响应
                //    如果你想让 PFCP 里的 remove_pdr/remove_qer 真正被 UPF 层解析删除，
                //    还需要 upf_n4_handle_session_modification_request() 内部正确处理 remove_xxx。
                //    不想做任何 session 中 PDR/QER 层面的删除也没问题，但一定要发回响应。
                upf_n4_handle_session_modification_request(sess, xact, req);
                break;
            }
            */

            //TC限速阶段: 存储ip和mbr,用于反复安装rule和删除rule的场景，不存储的话N4接口不会再有这两个信息
            char ue_ip[16] = {0};     // UE 地址（应作为源 IP）
            char server_ip[16] = {0}; // 服务器地址（应作为目的 IP）
            uint64_t mbr_ul = 0;      // 上行 MBR (bps)

            // 遍历 Create-PDR IE 数组（固定大小 16 个）
            for (int i = 0; i < 16; i++) {
                if (message->pfcp_session_modification_request.create_pdr[i].presence) {
                    // 打印 Create-PDR 的关键信息
                    unsigned int pdr_id = *(uint16_t *)&(message->pfcp_session_modification_request.create_pdr[i].pdr_id);
                    unsigned int precedence = *(uint32_t *)&(message->pfcp_session_modification_request.create_pdr[i].precedence);
                    ogs_info("Create PDR[%d] present:", i);
                    ogs_info("    pdr_id: %u", pdr_id);
                    ogs_info("    precedence: %u", precedence);
            
                    // 如果 PDI 存在，则打印 PDI 的内容
                    if (message->pfcp_session_modification_request.create_pdr[i].pdi.presence) {
                        ogs_pfcp_tlv_pdi_t *pdi = &message->pfcp_session_modification_request.create_pdr[i].pdi;
                        unsigned int src_if = *(uint8_t *)&(pdi->source_interface);
                        ogs_info("PDI source_interface: %u", src_if);

                        // 打印 PDI 中的 SDF Filter 数组 (最多8个)
                        for (int j = 0; j < 8; j++) {
                            if (pdi->sdf_filter[j].presence) {
                                ogs_info("    PDI SDF Filter[%d]: presence=%d, len=%d", j,
                                         (int)pdi->sdf_filter[j].presence, (int)pdi->sdf_filter[j].len);
                                if ((int)pdi->sdf_filter[j].len > 4) {
                                    int txt_len = (int)pdi->sdf_filter[j].len - 4;
                                    char *txt = (char *)pdi->sdf_filter[j].data + 4;
                                    ogs_info("    PDI SDF Filter[%d] as string: %.*s", j, txt_len, txt);

                                    // 限速阶段:
                                    // 预期 SDF 格式："permit out ip from <server_ip> to <ue_ip>"
                                    if (strncmp(txt, "permit out ip from ", 19) == 0){
                                        if (sscanf(txt, "permit out ip from %15s to %15s", server_ip, ue_ip) == 2){
                                            ogs_info("Extracted server IP: %s, UE IP: %s", server_ip, ue_ip);
                                            /* 缓存到 session 中 */
                                            strncpy(sess->cached_server_ip, server_ip, sizeof(sess->cached_server_ip));
                                            strncpy(sess->cached_ue_ip, ue_ip, sizeof(sess->cached_ue_ip));
                                        }
                                        else{
                                            ogs_info("Failed to extract both IPs from SDF string");
                                        }
                                    }
                                } else {
                                    ogs_info("    PDI SDF Filter[%d] as string: (too short)", j);
                                }
                                // 同时打印十六进制数据供参考
                                /*
                                {
                                    char hexbuf[256] = {0};
                                    int pos = 0;
                                    for (int k = 0; k < (int)pdi->sdf_filter[j].len && pos < (int)(sizeof(hexbuf) - 4); k++) {
                                        pos += snprintf(hexbuf + pos, sizeof(hexbuf) - pos, "%02x ", ((unsigned char *)pdi->sdf_filter[j].data)[k]);
                                    }
                                    ogs_info("    PDI SDF Filter[%d] hex: %s", j, hexbuf);
                                }*/
                            } else {
                                ogs_info("    PDI SDF Filter[%d]: not present", j);
                            }
                        
                        }
                    }
                }
            }


            // 如果此次修改中没有 Create PDR IE（即 ue_ip/server_ip为空），尝试使用会话缓存
            // 对应反复下发和删除qos flow场景，PFCP中只有update QER，这里通过读取缓存中的设置来继续更改qos MBR
            // 缓存配置在context.h中的typedef struct upf_sess_s 函数中,如下
            /*
            char cached_ue_ip[16];
            char cached_server_ip[16];
            */
            if (strlen(ue_ip) == 0 || strlen(server_ip) == 0){
                if (strlen(sess->cached_ue_ip) > 0 && strlen(sess->cached_server_ip) > 0){
                    strncpy(ue_ip, sess->cached_ue_ip, sizeof(ue_ip));
                    strncpy(server_ip, sess->cached_server_ip, sizeof(server_ip));
                    ogs_info("Using cached IPs: UE = %s, Server = %s", ue_ip, server_ip);
                }
                else{
                    ogs_info("No Create PDR IE found and no cached IPs available");
                }
            }
            
            // 如果想使用UE IP和Server IP信息，那么
            // 放到上边这段代码下，因为上边这段代码才能读取存储到session中的UE IP和Server IP
            if (remove_requested)
            {
                const char *interface = "ogstun";
                char tc_cmd[512];
                ogs_info("Detected remove IE in PFCP message, clearing the specific tc rules...");

                // 删除特别速率（下边用于提升的速率）：filter prio 1 和 class 1:10
                snprintf(tc_cmd, sizeof(tc_cmd), "sudo tc filter del dev %s protocol ip parent 1: prio 1", interface);
                system(tc_cmd);
                snprintf(tc_cmd, sizeof(tc_cmd), "sudo tc class del dev %s classid 1:10", interface);
                system(tc_cmd);

                ogs_info("✅ The specific tc rules have been cleared on interface %s for UE %s to Server %s", interface, ue_ip, server_ip);
                // 2) 继续处理 PFCP 请求 -> 产生响应
                //    如果你想让 PFCP 里的 remove_pdr/remove_qer 真正被 UPF 层解析删除，
                //    还需要 upf_n4_handle_session_modification_request() 内部正确处理 remove_xxx。
                //    不想做任何 session 中 PDR/QER 层面的删除也没问题，但一定要发回响应。
                upf_n4_handle_session_modification_request(sess, xact, req);
                break;
            }

            /*源码*/
            upf_n4_handle_session_modification_request(
                sess, xact, &message->pfcp_session_modification_request);

            //调试 遍历 Create QER IE 数组（假设最大数量为 OGS_MAX_NUM_OF_QER）
            uint8_t cause_value = 0;
            uint8_t offending_ie_value = 0;
            for (int i = 0; i < OGS_MAX_NUM_OF_QER; i++){
                if (message->pfcp_session_modification_request.create_qer[i].presence){
                    ogs_pfcp_qer_t *qer = ogs_pfcp_handle_create_qer(&sess->pfcp,
                                                                     &message->pfcp_session_modification_request.create_qer[i],
                                                                     &cause_value, &offending_ie_value);
                    if (qer == NULL)
                        break;
                    ogs_info("📊 pfcp-sm Received QER with MBR Info: UL=%" PRIu64 ", DL=%" PRIu64, qer->mbr.uplink, qer->mbr.downlink);
                    ogs_info("📊 pfcp-sm Received QER with GBR Info: UL=%" PRIu64 ", DL=%" PRIu64, qer->gbr.uplink, qer->gbr.downlink);

                    // 限速阶段
                    //  提取 MBR 信息
                    mbr_ul = qer->mbr.uplink;
                    //mbr_dl = qer->mbr.downlink;
                }
                // 如果 create_qer 没有设置 MBR，则再尝试遍历 Update QER IE 数组
                if (mbr_ul == 0){
                    for (int i = 0; i < OGS_MAX_NUM_OF_QER; i++){
                        if (message->pfcp_session_modification_request.update_qer[i].presence){
                            ogs_pfcp_qer_t *qer = ogs_pfcp_handle_update_qer(&sess->pfcp,
                                                                             &message->pfcp_session_modification_request.update_qer[i],
                                                                             &cause_value, &offending_ie_value);
                            if (qer == NULL)
                                break;
                            ogs_info("📊 pfcp-sm Received UPDATE QER with MBR Info: UL=%" PRIu64 ", DL=%" PRIu64,
                                     qer->mbr.uplink, qer->mbr.downlink);
                            ogs_info("📊 pfcp-sm Received UPDATE QER with GBR Info: UL=%" PRIu64 ", DL=%" PRIu64,
                                     qer->gbr.uplink, qer->gbr.downlink);

                            // 限速阶段：提取 MBR 信息
                            mbr_ul = qer->mbr.uplink;
                            // mbr_dl = qer->mbr.downlink;
                        }
                    }
                }
            }

            // 限速阶段
            // 如果成功提取到 UE IP、服务器 IP和上行 MBR，则设置 tc 限速
            if (strlen(ue_ip) > 0 && strlen(server_ip) > 0 && mbr_ul > 0)
            {
                char tc_cmd[512];
                const char *interface = "ogstun";

                ogs_info("Extracted mbr_ul: %" PRIu64 " bps", mbr_ul);

                // 转换为 Mbit 字符串（例如 "8mbit"）
                // QER 提速速率（例如8Mbit）；原先全局限速为2Mbit - 新增加04-15
                uint32_t high_rate_mbit = (uint32_t)(mbr_ul / 1000000);
                char high_rate_str[32] = {0};
                snprintf(high_rate_str, sizeof(high_rate_str), "%umbit", high_rate_mbit);
                ogs_info("Using high rate: %s", high_rate_str);



                // 🔻 下行限速设置（UE 接收方向）
                // 目标：匹配 ip dst == UE IP 且 ip src == 服务器 IP
                // 1. 添加 root qdisc（HTB），默认流归入 class 1:10（2Mbit）
                snprintf(tc_cmd, sizeof(tc_cmd),
                         "sudo tc class add dev %s parent 1:1 classid 1:10 htb rate %s burst 30k",
                         interface, high_rate_str);
                system(tc_cmd);
                snprintf(tc_cmd, sizeof(tc_cmd),
                         "sudo tc filter add dev %s protocol ip parent 1: prio 1 u32 match ip src %s match ip dst %s flowid 1:10",
                         interface, server_ip, ue_ip);
                system(tc_cmd);

                ogs_info("✅ Applied enhanced TC rules on %s: %s for dlink traffic speed from %s to server %s", interface, high_rate_str, ue_ip, server_ip);
            }
            else{
                ogs_error("Failed to extract UE IP, server IP or UL MBR for tc rate limiting in modification");
            }

            /*源码*/
            break;       
    
        case OGS_PFCP_SESSION_DELETION_REQUEST_TYPE:
            upf_n4_handle_session_deletion_request(
                sess, xact, &message->pfcp_session_deletion_request);
            break;
        case OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE:
            upf_n4_handle_session_report_response(
                sess, xact, &message->pfcp_session_report_response);
            break;
        default:
            ogs_error("Not implemented PFCP message type[%d]",
                    message->h.type);
            break;
        }

        break;
    case UPF_EVT_N4_TIMER:
        switch(e->timer_id) {
        case UPF_TIMER_NO_HEARTBEAT:
            node = e->pfcp_node;
            ogs_assert(node);

            ogs_assert(OGS_OK ==
                ogs_pfcp_send_heartbeat_request(node, node_timeout));
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    upf_timer_get_name(e->timer_id), e->timer_id);
            break;
        }
        break;
    case UPF_EVT_N4_NO_HEARTBEAT:
        ogs_warn("No Heartbeat from SMF %s",
                ogs_sockaddr_to_string_static(node->addr_list));
        OGS_FSM_TRAN(s, upf_pfcp_state_will_associate);
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

void upf_pfcp_state_exception(ogs_fsm_t *s, upf_event_t *e)
{
    ogs_assert(s);
    ogs_assert(e);

    upf_sm_debug(e);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;
    case OGS_FSM_EXIT_SIG:
        break;
    default:
        ogs_error("Unknown event %s", upf_event_get_name(e));
        break;
    }
}

static void pfcp_restoration(ogs_pfcp_node_t *node)
{
    upf_sess_t *sess = NULL, *next = NULL;
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];

    ogs_list_for_each_safe(&upf_self()->sess_list, next, sess) {
        if (node == sess->pfcp_node) {
            ogs_info("DELETION: F-SEID[UP:0x%lx CP:0x%lx] IPv4[%s] IPv6[%s]",
                (long)sess->upf_n4_seid, (long)sess->smf_n4_f_seid.seid,
                sess->ipv4 ? OGS_INET_NTOP(&sess->ipv4->addr, buf1) : "",
                sess->ipv6 ? OGS_INET6_NTOP(&sess->ipv6->addr, buf2) : "");
            upf_sess_remove(sess);
        }
    }
}

static void node_timeout(ogs_pfcp_xact_t *xact, void *data)
{
    int rv;

    upf_event_t *e = NULL;
    uint8_t type;

    ogs_assert(xact);
    type = xact->seq[0].type;

    switch (type) {
    case OGS_PFCP_HEARTBEAT_REQUEST_TYPE:
        ogs_assert(data);

        e = upf_event_new(UPF_EVT_N4_NO_HEARTBEAT);
        e->pfcp_node = data;

        rv = ogs_queue_push(ogs_app()->queue, e);
        if (rv != OGS_OK) {
            ogs_error("ogs_queue_push() failed:%d", (int)rv);
            upf_event_free(e);
        }
        break;
    case OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE:
        break;
    default:
        ogs_error("Not implemented [type:%d]", type);
        break;
    }
}
