package db

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

func Connect(ctx context.Context) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://tankada:tankada@postgres:5432/tankada?sslmode=disable"
	}

	var err error
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	return pool.Ping(ctx)
}

func Close() {
	if pool != nil {
		pool.Close()
	}
}

type QueryResult struct {
	Columns  []string        `json:"columns"`
	Rows     [][]interface{} `json:"rows"`
	RowCount int             `json:"row_count"`
}

// Execute runs a read-only query scoped to a tenant.
// Each call opens a transaction, switches to the tankada_app role (non-superuser,
// subject to RLS), and sets app.tenant_id for the duration of that transaction.
// Both settings reset automatically when the transaction ends; no pool leakage.
func Execute(ctx context.Context, query, tenantID string) (*QueryResult, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE tankada_app"); err != nil {
		return nil, fmt.Errorf("set role: %w", err)
	}
	if tenantID != "" {
		// SET LOCAL does not accept parameters; set_config(..., true) is the
		// parameterized equivalent and scopes the value to the current transaction.
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
			return nil, fmt.Errorf("set tenant: %w", err)
		}
	}

	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query execution: %w", err)
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	cols := make([]string, len(fields))
	for i, f := range fields {
		cols[i] = string(f.Name)
	}

	var result [][]interface{}
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, fmt.Errorf("row scan: %w", err)
		}
		result = append(result, vals)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration: %w", err)
	}

	return &QueryResult{
		Columns:  cols,
		Rows:     result,
		RowCount: len(result),
	}, nil
}
