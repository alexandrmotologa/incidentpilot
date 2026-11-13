package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alexandrmotologa/incidentpilot/pkg/models"
	_ "modernc.org/sqlite"
)

type Store struct {
	dbPath string
	db     *sql.DB
	mu     sync.RWMutex
}

func NewStore(dbPath string) (*Store, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		_ = os.MkdirAll(dir, 0755)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite works safest with single writer connection in WAL mode

	s := &Store{
		dbPath: dbPath,
		db:     db,
	}

	if err := s.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) initialize() error {
	queries := []string{
		"PRAGMA journal_mode=WAL;",
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			fingerprint TEXT NOT NULL,
			service TEXT NOT NULL,
			status TEXT NOT NULL,
			alert_count INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			record_json TEXT NOT NULL
		);`,
		"CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents(fingerprint, created_at);",
		"CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);",
		`CREATE TABLE IF NOT EXISTS rollbacks (
			id TEXT PRIMARY KEY,
			incident_id TEXT NOT NULL,
			target_version TEXT NOT NULL,
			provider TEXT NOT NULL,
			status TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			executed_at TEXT NOT NULL,
			output TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT ''
		);`,
	}

	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			// Some pragmas return rows, ignore if just pragma
			if !strings.HasPrefix(q, "PRAGMA") {
				return fmt.Errorf("migration query failed: %w", err)
			}
		}
	}
	return nil
}

// Helper to execute query on db
func (s *Store) exec(query string, args ...any) error {
	_, err := s.db.Exec(query, args...)
	return err
}

func (s *Store) SaveIncident(ctx context.Context, record *models.IncidentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	record.UpdatedAt = time.Now().UTC()
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to serialize incident: %w", err)
	}

	query := `
	INSERT INTO incidents (
		id, fingerprint, service, status, alert_count, created_at, updated_at, record_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		status = excluded.status,
		alert_count = excluded.alert_count,
		updated_at = excluded.updated_at,
		record_json = excluded.record_json;
	`

	_, err = s.db.ExecContext(ctx, query,
		record.ID,
		record.Event.Fingerprint,
		record.Event.Service,
		string(record.Status),
		record.AlertCount,
		record.CreatedAt.Format(time.RFC3339Nano),
		record.UpdatedAt.Format(time.RFC3339Nano),
		string(payload),
	)
	return err
}

func (s *Store) GetIncident(ctx context.Context, id string) (*models.IncidentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRowContext(ctx, "SELECT record_json FROM incidents WHERE id = ?", id)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var record models.IncidentRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return nil, fmt.Errorf("corrupt incident record json: %w", err)
	}
	return &record, nil
}

func (s *Store) ListIncidents(ctx context.Context, limit int, service, severity, status string) ([]models.IncidentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 500 {
		limit = 50
	}

	baseQuery := "SELECT record_json FROM incidents"
	var clauses []string
	var args []any

	if service != "" {
		clauses = append(clauses, "LOWER(service) LIKE ?")
		args = append(args, "%"+strings.ToLower(service)+"%")
	}
	if status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, status)
	}

	if len(clauses) > 0 {
		baseQuery += " WHERE " + strings.Join(clauses, " AND ")
	}

	fetchLimit := limit
	if severity != "" {
		fetchLimit = limit * 3
	}
	baseQuery += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, fetchLimit)

	rows, err := s.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.IncidentRecord
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var rec models.IncidentRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if severity != "" && string(rec.Event.Severity) != severity {
			continue
		}
		results = append(results, rec)
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

func (s *Store) FindActiveByFingerprint(ctx context.Context, fingerprint string, windowSeconds int) (*models.IncidentRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().UTC().Add(-time.Duration(windowSeconds) * time.Second).Format(time.RFC3339Nano)
	query := `
	SELECT record_json FROM incidents
	WHERE fingerprint = ?
	  AND created_at >= ?
	  AND status NOT IN (?, ?, ?)
	ORDER BY created_at DESC
	LIMIT 1;
	`

	row := s.db.QueryRowContext(ctx, query, fingerprint, cutoff, string(models.StatusResolved), string(models.StatusDismissed), string(models.StatusRolledBack))
	var raw string
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	var rec models.IncidentRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) SaveRollback(ctx context.Context, rb *models.RollbackRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
	INSERT INTO rollbacks (
		id, incident_id, target_version, provider, status,
		requested_by, executed_at, output, error
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		status = excluded.status,
		output = excluded.output,
		error = excluded.error;
	`

	_, err := s.db.ExecContext(ctx, query,
		rb.ID,
		rb.IncidentID,
		rb.TargetVersion,
		rb.Provider,
		rb.Status,
		rb.RequestedBy,
		rb.ExecutedAt.Format(time.RFC3339Nano),
		rb.Output,
		rb.Error,
	)
	return err
}

func (s *Store) ComputeMetrics(ctx context.Context) (*models.SreMetrics, error) {
	records, err := s.ListIncidents(ctx, 500, "", "", "")
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return &models.SreMetrics{}, nil
	}

	activeCount := 0
	resolvedCount := 0
	var totalInvMs int64
	var invCount int
	var mttrSum float64
	var mttrCount int
	var correlatedCount int

	for _, r := range records {
		switch r.Status {
		case models.StatusInvestigating, models.StatusBriefSent, models.StatusRollbackPending, models.StatusRollbackFailed:
			activeCount++
		case models.StatusResolved, models.StatusRolledBack:
			resolvedCount++
		}

		if r.Brief != nil && r.Brief.InvestigationDurationMs > 0 {
			totalInvMs += r.Brief.InvestigationDurationMs
			invCount++
		}
		if r.MTTRSeconds != nil {
			mttrSum += *r.MTTRSeconds
			mttrCount++
		}
		if r.Brief != nil && r.Brief.TopCandidate != nil {
			correlatedCount++
		}
	}

	var avgInv float64
	if invCount > 0 {
		avgInv = math.Round(float64(totalInvMs)/float64(invCount)*10) / 10
	}

	var avgMTTR *float64
	if mttrCount > 0 {
		val := math.Round(mttrSum/float64(mttrCount)*10) / 10
		avgMTTR = &val
	}

	hitRate := math.Round((float64(correlatedCount)/float64(len(records)))*1000) / 10

	return &models.SreMetrics{
		TotalIncidents:     len(records),
		ActiveIncidents:    activeCount,
		ResolvedIncidents:  resolvedCount,
		AvgInvestigationMs: avgInv,
		AvgMTTRSeconds:     avgMTTR,
		CorrelationHitRate: hitRate,
	}, nil
}
