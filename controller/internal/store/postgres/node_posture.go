package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type nodePostureRepo struct{ pool *pgxpool.Pool }

// BulkInsert writes posture samples into ts_node_posture via CopyFrom.
func (r *nodePostureRepo) BulkInsert(ctx context.Context, points []store.PosturePoint) error {
	if len(points) == 0 {
		return nil
	}
	columns := []string{
		"time", "node_id",
		"filter_rules", "validated_clients",
		"syn_cookies_replied", "syn_cookies_validated", "syn_cookies_dropped",
		"emergency_drops", "burst_alerts", "redirect_ok", "redirect_err",
		"af_xdp_active", "af_xdp_umem_drops", "af_xdp_rx",
	}
	rows := make([][]any, len(points))
	for i, p := range points {
		rows[i] = []any{
			p.Time, p.NodeID,
			int64(p.FilterRules), int64(p.ValidatedClients),
			int64(p.SynCookiesReplied), int64(p.SynCookiesValidated), int64(p.SynCookiesDropped),
			int64(p.EmergencyDrops), int64(p.BurstAlerts), int64(p.RedirectOk), int64(p.RedirectErr),
			p.AFXDPActive, int64(p.AFXDPUmemDrops), int64(p.AFXDPRX),
		}
	}
	_, err := r.pool.CopyFrom(ctx, pgx.Identifier{"ts_node_posture"}, columns, pgx.CopyFromRows(rows))
	return err
}

// QueryHistory returns bucketed posture samples. Counters aggregate with max()
// (cumulative semantics), af_xdp_active with bool_or.
func (r *nodePostureRepo) QueryHistory(ctx context.Context, filter store.PostureFilter) ([]store.PosturePoint, error) {
	bucket := "1 minute"
	switch filter.Resolution {
	case "5s":
		bucket = "15 seconds"
	case "5min":
		bucket = "5 minutes"
	}

	var conds []string
	var args []any
	argN := 1
	if !filter.From.IsZero() {
		conds = append(conds, fmt.Sprintf("time >= $%d", argN))
		args = append(args, filter.From)
		argN++
	}
	if !filter.To.IsZero() {
		conds = append(conds, fmt.Sprintf("time <= $%d", argN))
		args = append(args, filter.To)
		argN++
	}
	if filter.NodeID != "" {
		conds = append(conds, fmt.Sprintf("node_id = $%d", argN))
		args = append(args, filter.NodeID)
		argN++
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	limit := clampLimit(filter.Limit)

	q := fmt.Sprintf(`
		SELECT time_bucket('%s', time) AS bucket, node_id,
			   max(filter_rules)::BIGINT, max(validated_clients)::BIGINT,
			   max(syn_cookies_replied)::BIGINT, max(syn_cookies_validated)::BIGINT,
			   max(syn_cookies_dropped)::BIGINT, max(emergency_drops)::BIGINT,
			   max(burst_alerts)::BIGINT, max(redirect_ok)::BIGINT, max(redirect_err)::BIGINT,
			   bool_or(af_xdp_active), max(af_xdp_umem_drops)::BIGINT, max(af_xdp_rx)::BIGINT
		FROM ts_node_posture%s
		GROUP BY bucket, node_id
		ORDER BY bucket
		LIMIT %d`, bucket, where, limit)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []store.PosturePoint
	for rows.Next() {
		var p store.PosturePoint
		if err := rows.Scan(&p.Time, &p.NodeID,
			&p.FilterRules, &p.ValidatedClients,
			&p.SynCookiesReplied, &p.SynCookiesValidated, &p.SynCookiesDropped,
			&p.EmergencyDrops, &p.BurstAlerts, &p.RedirectOk, &p.RedirectErr,
			&p.AFXDPActive, &p.AFXDPUmemDrops, &p.AFXDPRX); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}
