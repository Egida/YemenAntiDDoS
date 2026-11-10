package api

import (
	"net/http"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

// postureHistoryLimit mirrors the resolution-dependent caps of queryTimeseries.
func postureHistoryLimit(resolution string) int {
	switch resolution {
	case "5s":
		return 1920 // 8h of 15s buckets
	case "5min":
		return 2016 // 7d of 5min buckets
	default:
		return 2880 // 48h of 1min buckets
	}
}

// postureHistory serves GET /api/nodes/posture/history.
func postureHistory(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		if deps.Store == nil {
			errResponse(c, http.StatusServiceUnavailable, "store unavailable")
			return
		}
		resolution := c.DefaultQuery("resolution", "1min")
		switch resolution {
		case "5s", "1min", "5min":
		default:
			errResponse(c, http.StatusBadRequest, "resolution must be '5s', '1min', or '5min'")
			return
		}
		filter := store.PostureFilter{
			NodeID:     c.Query("node_id"),
			Resolution: resolution,
			Limit:      postureHistoryLimit(resolution),
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.From = t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.To = t
			}
		}
		if filter.From.IsZero() {
			filter.From = time.Now().Add(-1 * time.Hour)
		}
		if filter.To.IsZero() {
			filter.To = time.Now()
		}
		points, err := deps.Store.NodePosture().QueryHistory(c.Request.Context(), filter)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, points)
	}
}
