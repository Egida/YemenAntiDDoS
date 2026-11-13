package api

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/d80y6/YemenDDoS/controller/internal/bgp"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// syncBGPSpeakerPeers pushes current enabled connectors with peering details
// into the embedded speaker. Best-effort: DB state is authoritative; the
// next CRUD operation retries.
func syncBGPSpeakerPeers(c *gin.Context, deps Dependencies) error {
	sp := bgp.Shared()
	if sp == nil {
		return nil
	}
	conns, err := deps.Store.BGPConnectors().List(c)
	if err != nil {
		return err
	}
	peers := make([]bgp.Peer, 0, len(conns))
	for _, conn := range conns {
		if !conn.Enabled || conn.NeighborIP == "" || conn.NeighborASN == 0 {
			continue
		}
		peers = append(peers, bgp.Peer{
			ConnectorID: conn.ID, Name: conn.Name,
			NeighborIP: conn.NeighborIP, NeighborASN: uint32(conn.NeighborASN),
			MD5Password: conn.MD5Password, AddressFamily: conn.AddressFamily,
		})
	}
	return sp.SyncPeers(c, peers)
}

func listBGPConnectors(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		list, err := deps.Store.BGPConnectors().List(c)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		ok(c, list)
	}
}

func getBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		if conn == nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		ok(c, conn)
	}
}

func createBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name          string `json:"name" binding:"required"`
			BGPASN        *int64 `json:"bgp_asn"`
			AddressFamily string `json:"address_family"`
			Enabled       *bool  `json:"enabled"`
			Description   string `json:"description"`
			Vendor        string `json:"vendor"`
			Flowspec      *bool  `json:"flowspec_enabled"`
			NeighborIP    string `json:"neighbor_ip"`
			NeighborASN   *int64 `json:"neighbor_asn"`
			MD5Password   string `json:"md5_password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.BGPASN == nil {
			errResponse(c, http.StatusBadRequest, "bgp_asn is required")
			return
		}
		if *req.BGPASN < 1 || *req.BGPASN > 4294967295 {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("bgp_asn must be between 1 and 4294967295, got %d", *req.BGPASN))
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		neighborASN := 0
		if req.NeighborASN != nil {
			if *req.NeighborASN < 1 || *req.NeighborASN > 4294967295 {
				errResponse(c, http.StatusBadRequest, "neighbor_asn must be between 1 and 4294967295")
				return
			}
			neighborASN = int(*req.NeighborASN)
		}
		if req.AddressFamily == "" {
			req.AddressFamily = "auto"
		}
		if req.AddressFamily != "auto" && req.AddressFamily != "ipv4" && req.AddressFamily != "ipv6" {
			errResponse(c, http.StatusBadRequest, `address_family must be "auto", "ipv4" or "ipv6"`)
			return
		}
		neighborIP := strings.TrimSpace(req.NeighborIP)
		if enabled && (neighborIP == "" || neighborASN == 0) {
			errResponse(c, http.StatusBadRequest,
				"an enabled connector needs neighbor_ip and neighbor_asn (BGP peering details)")
			return
		}
		if neighborIP != "" && net.ParseIP(neighborIP) == nil {
			errResponse(c, http.StatusBadRequest, "neighbor_ip must be an IP address")
			return
		}
		flowspecEnabled := false
		if req.Flowspec != nil {
			flowspecEnabled = *req.Flowspec
		}
		conn := &store.BGPConnector{
			Name:            req.Name,
			BGPASN:          int(*req.BGPASN),
			AddressFamily:   req.AddressFamily,
			Enabled:         enabled,
			Description:     req.Description,
			Vendor:          req.Vendor,
			FlowspecEnabled: flowspecEnabled,
			NeighborIP:      neighborIP,
			NeighborASN:     neighborASN,
			MD5Password:     req.MD5Password,
		}
		id, err := deps.Store.BGPConnectors().Create(c, conn)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		conn.ID = id
		if err := syncBGPSpeakerPeers(c, deps); err != nil {
			log.Printf("api: bgp peer sync after connector create: %v", err)
		}
		publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "create", makeDiff(nil, conn))
		created(c, gin.H{"id": id})
	}
}

func updateBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		if conn == nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		var req struct {
			Name          *string `json:"name"`
			BGPASN        *int64  `json:"bgp_asn"`
			AddressFamily *string `json:"address_family"`
			Enabled       *bool   `json:"enabled"`
			Description   *string `json:"description"`
			Vendor        *string `json:"vendor"`
			Flowspec      *bool   `json:"flowspec_enabled"`
			NeighborIP    *string `json:"neighbor_ip"`
			NeighborASN   *int64  `json:"neighbor_asn"`
			MD5Password   *string `json:"md5_password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		old := *conn
		if req.Name != nil && *req.Name != "" {
			conn.Name = *req.Name
		}
		if req.BGPASN != nil {
			if *req.BGPASN < 1 || *req.BGPASN > 4294967295 {
				errResponse(c, http.StatusBadRequest, fmt.Sprintf("bgp_asn must be between 1 and 4294967295, got %d", *req.BGPASN))
				return
			}
			conn.BGPASN = int(*req.BGPASN)
		}
		if conn.BGPASN < 1 || conn.BGPASN > 4294967295 {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("bgp_asn must be between 1 and 4294967295, got %d", conn.BGPASN))
			return
		}
		if req.AddressFamily != nil && *req.AddressFamily != "" {
			conn.AddressFamily = *req.AddressFamily
		}
		if conn.AddressFamily != "auto" && conn.AddressFamily != "ipv4" && conn.AddressFamily != "ipv6" {
			errResponse(c, http.StatusBadRequest, `address_family must be "auto", "ipv4" or "ipv6"`)
			return
		}
		if req.Enabled != nil {
			conn.Enabled = *req.Enabled
		}
		if req.Description != nil {
			conn.Description = *req.Description
		}
		if req.Vendor != nil {
			conn.Vendor = *req.Vendor
		}
		if req.Flowspec != nil {
			conn.FlowspecEnabled = *req.Flowspec
		}
		if req.NeighborIP != nil {
			conn.NeighborIP = strings.TrimSpace(*req.NeighborIP)
		}
		if req.NeighborASN != nil {
			if *req.NeighborASN < 1 || *req.NeighborASN > 4294967295 {
				errResponse(c, http.StatusBadRequest, "neighbor_asn must be between 1 and 4294967295")
				return
			}
			conn.NeighborASN = int(*req.NeighborASN)
		}
		if req.MD5Password != nil {
			conn.MD5Password = *req.MD5Password
		}
		if conn.Enabled && (conn.NeighborIP == "" || conn.NeighborASN == 0) {
			errResponse(c, http.StatusBadRequest,
				"an enabled connector needs neighbor_ip and neighbor_asn (BGP peering details)")
			return
		}
		if conn.NeighborIP != "" && net.ParseIP(conn.NeighborIP) == nil {
			errResponse(c, http.StatusBadRequest, "neighbor_ip must be an IP address")
			return
		}
		if err := deps.Store.BGPConnectors().Update(c, conn); err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if err := syncBGPSpeakerPeers(c, deps); err != nil {
			log.Printf("api: bgp peer sync after connector update: %v", err)
		}
		if conn.Enabled && deps.ActionEngine != nil {
			go deps.ActionEngine.SweepEnabledBGPConnector(id)
		}
		publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "update", makeDiff(old, conn))
		ok(c, gin.H{"ok": true})
	}
}

func deleteBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		count, err := deps.Store.Responses().CountActionsByBGPConnector(c, id)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if count > 0 {
			errResponse(c, http.StatusConflict, fmt.Sprintf("connector in use by %d action(s)", count))
			return
		}
		live, err := deps.Store.BGPAnnouncements().CountLiveByConnector(c, id)
		if err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if live > 0 {
			errResponse(c, http.StatusConflict, fmt.Sprintf("connector still has %d announcements in flight", live))
			return
		}
		old, _ := deps.Store.BGPConnectors().Get(c, id)
		if err := deps.Store.BGPConnectors().Delete(c, id); err != nil {
			dbError(c, "bgp connector ", err)
			return
		}
		if err := syncBGPSpeakerPeers(c, deps); err != nil {
			log.Printf("api: bgp peer sync after connector delete: %v", err)
		}
		if old != nil {
			publishAfterChange(c, deps, "bgp_connector", strconv.Itoa(id), "delete", makeDiff(old, nil))
		}
		ok(c, gin.H{"ok": true})
	}
}

// testBGPConnector reports the live session state of this connector's peer.
func testBGPConnector(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		conn, err := deps.Store.BGPConnectors().Get(c, id)
		if err != nil || conn == nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}
		sp := bgp.Shared()
		if sp == nil {
			errResponse(c, http.StatusConflict, "bgp speaker not configured (Settings → BGP Instance)")
			return
		}
		for _, st := range sp.PeerStates(c) {
			if st.ConnectorID == conn.ID {
				if st.SessionUp {
					ok(c, gin.H{"ok": true, "output": "session established with " + st.NeighborIP})
				} else {
					ok(c, gin.H{"ok": false, "error": "session down", "output": "session down with " + st.NeighborIP})
				}
				return
			}
		}
		errResponse(c, http.StatusConflict, "connector has no peering details configured")
	}
}
