package api

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// The controller is single-instance; this mutex serializes partial updates.
var bgpInstanceUpdateMu sync.Mutex

func getBGPInstance(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		inst, err := deps.Store.BGPInstances().Get(c)
		if err != nil {
			dbError(c, "bgp instance ", err)
			return
		}
		if inst == nil {
			ok(c, gin.H{"configured": false})
			return
		}
		ok(c, gin.H{"configured": true, "instance": inst, "speaker_running": bgp.Shared() != nil})
	}
}

func updateBGPInstance(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			LocalASN    *int64  `json:"local_asn"`
			RouterID    *string `json:"router_id"`
			ListenPort  *int64  `json:"listen_port"`
			RTBHNextHop *string `json:"rtbh_next_hop"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		bgpInstanceUpdateMu.Lock()
		defer bgpInstanceUpdateMu.Unlock()
		inst, err := deps.Store.BGPInstances().Get(c)
		if err != nil {
			dbError(c, "bgp instance ", err)
			return
		}
		if inst == nil {
			inst = &store.BGPInstance{ListenPort: 179}
		}
		if req.LocalASN != nil {
			if *req.LocalASN < 1 || *req.LocalASN > 4294967295 {
				errResponse(c, http.StatusBadRequest, "local_asn must be between 1 and 4294967295")
				return
			}
			inst.LocalASN = int(*req.LocalASN)
		}
		if req.RouterID != nil {
			ip := net.ParseIP(strings.TrimSpace(*req.RouterID))
			if ip == nil || ip.To4() == nil {
				errResponse(c, http.StatusBadRequest, "router_id must be an IPv4 address")
				return
			}
			inst.RouterID = strings.TrimSpace(*req.RouterID)
		}
		if req.ListenPort != nil {
			if *req.ListenPort < 0 || *req.ListenPort > 65535 {
				errResponse(c, http.StatusBadRequest, "listen_port must be 0-65535 (0 disables inbound)")
				return
			}
			inst.ListenPort = int(*req.ListenPort)
		}
		if req.RTBHNextHop != nil {
			v := strings.TrimSpace(*req.RTBHNextHop)
			if v != "" && net.ParseIP(v) == nil {
				errResponse(c, http.StatusBadRequest, "rtbh_next_hop must be an IP address")
				return
			}
			inst.RTBHNextHop = v
		}
		if inst.LocalASN <= 0 || inst.RouterID == "" {
			errResponse(c, http.StatusBadRequest, "local_asn and router_id are required")
			return
		}
		if err := deps.Store.BGPInstances().Upsert(c, inst); err != nil {
			dbError(c, "bgp instance ", err)
			return
		}
		publishAfterChange(c, deps, "bgp_instance", "1", "update",
			jsonOrNil(map[string]any{"local_asn": inst.LocalASN, "router_id": inst.RouterID}))
		ok(c, gin.H{"ok": true, "restart_required": true,
			"note": "instance identity changes take effect after controller restart"})
	}
}

// listBGPPeers returns live session state for the connectors page.
func listBGPPeers(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		sp := bgp.Shared()
		if sp == nil {
			ok(c, gin.H{"peers": []gin.H{}, "speaker_running": false})
			return
		}
		states := sp.PeerStates(c)
		views := make([]gin.H, 0, len(states))
		for _, st := range states {
			views = append(views, gin.H{
				"connector_id": st.ConnectorID, "name": st.Name,
				"neighbor_ip": st.NeighborIP, "session_up": st.SessionUp,
			})
		}
		ok(c, gin.H{"peers": views, "speaker_running": true})
	}
}
