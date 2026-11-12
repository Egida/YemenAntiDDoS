package postgres

import (
	"context"
	"fmt"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

type bgpConnectorRepo struct{ pool *pgxpool.Pool }

const bgpConnectorCols = `id, name, bgp_asn, address_family, enabled, description,
	COALESCE(vendor, ''), COALESCE(flowspec_enabled, false),
	COALESCE(neighbor_ip, ''), COALESCE(neighbor_asn, 0), COALESCE(md5_password, ''), created_at, updated_at`

func (r *bgpConnectorRepo) List(ctx context.Context) ([]store.BGPConnector, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+bgpConnectorCols+` FROM bgp_connectors ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []store.BGPConnector
	for rows.Next() {
		var c store.BGPConnector
		if err := rows.Scan(&c.ID, &c.Name, &c.BGPASN,
			&c.AddressFamily, &c.Enabled, &c.Description, &c.Vendor, &c.FlowspecEnabled,
			&c.NeighborIP, &c.NeighborASN, &c.MD5Password, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

func (r *bgpConnectorRepo) Get(ctx context.Context, id int) (*store.BGPConnector, error) {
	var c store.BGPConnector
	err := r.pool.QueryRow(ctx,
		`SELECT `+bgpConnectorCols+` FROM bgp_connectors WHERE id=$1`, id).
		Scan(&c.ID, &c.Name, &c.BGPASN,
			&c.AddressFamily, &c.Enabled, &c.Description, &c.Vendor, &c.FlowspecEnabled,
			&c.NeighborIP, &c.NeighborASN, &c.MD5Password, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("bgp_connector %d: %w", id, err)
	}
	return &c, nil
}

func (r *bgpConnectorRepo) Create(ctx context.Context, c *store.BGPConnector) (int, error) {
	var id int
	err := r.pool.QueryRow(ctx,
		`INSERT INTO bgp_connectors (name, bgp_asn, address_family, enabled, description, vendor, flowspec_enabled, neighbor_ip, neighbor_asn, md5_password)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		c.Name, c.BGPASN, c.AddressFamily, c.Enabled, c.Description, c.Vendor, c.FlowspecEnabled,
		c.NeighborIP, c.NeighborASN, c.MD5Password).Scan(&id)
	return id, err
}

func (r *bgpConnectorRepo) Update(ctx context.Context, c *store.BGPConnector) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE bgp_connectors
		 SET name=$1, bgp_asn=$2, address_family=$3, enabled=$4, description=$5,
		     vendor=$6, flowspec_enabled=$7, neighbor_ip=$8, neighbor_asn=$9, md5_password=$10, updated_at=now()
		 WHERE id=$11`,
		c.Name, c.BGPASN, c.AddressFamily, c.Enabled, c.Description,
		c.Vendor, c.FlowspecEnabled, c.NeighborIP, c.NeighborASN, c.MD5Password, c.ID)
	return err
}

func (r *bgpConnectorRepo) Delete(ctx context.Context, id int) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM bgp_connectors WHERE id=$1`, id)
	return err
}
