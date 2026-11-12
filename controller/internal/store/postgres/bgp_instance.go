package postgres

import (
	"context"
	"errors"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type bgpInstanceRepo struct{ pool *pgxpool.Pool }

func (r *bgpInstanceRepo) Get(ctx context.Context) (*store.BGPInstance, error) {
	var inst store.BGPInstance
	err := r.pool.QueryRow(ctx,
		`SELECT local_asn, router_id, listen_port, rtbh_next_hop, updated_at FROM bgp_instance WHERE id=1`).
		Scan(&inst.LocalASN, &inst.RouterID, &inst.ListenPort, &inst.RTBHNextHop, &inst.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &inst, nil
}

func (r *bgpInstanceRepo) Upsert(ctx context.Context, inst *store.BGPInstance) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO bgp_instance (id, local_asn, router_id, listen_port, rtbh_next_hop, updated_at)
		 VALUES (1, $1, $2, $3, $4, now())
		 ON CONFLICT (id) DO UPDATE SET
		   local_asn=$1, router_id=$2, listen_port=$3, rtbh_next_hop=$4, updated_at=now()`,
		inst.LocalASN, inst.RouterID, inst.ListenPort, inst.RTBHNextHop)
	return err
}
