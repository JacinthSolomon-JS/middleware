package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	purgeChunk         = 5000
	purgeInterval      = 5 * time.Minute
	maxDropLogInterval = time.Second
)

// LogEvent represents a single traffic event for logging in database
type LogEvent struct {
	Timestamp   time.Time `json:"Timestamp"`
	Protocol    string    `json:"Protocol"` // DNS or TLS
	ClientIP    string    `json:"ClientIP"`
	Target      string    `json:"Target"` // Domain or SNI
	Action      string    `json:"Action"` // Allowed or Blocked
	BlockReason string    `json:"BlockReason"`
	MatchedBy   string    `json:"MatchedBy"`
}

// AnalyticsSummary Contains metrics for dashboard display
type AnalyticsSummary struct {
	TotalQueries int64 `json:"total_queries"`
	TotalBlocked int64 `json:"total_blocked"`
	TotalAllowed int64 `json:"total_allowed"`
}

// CustomSource is a runtime-added blocklist source
type CustomSource struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	URL       string    `json:"url"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// Database Initialization
type Database struct {
	db        *sql.DB
	logChan   chan LogEvent
	batchSize int
	flushFreq time.Duration
	wg        sync.WaitGroup
	cancel    context.CancelFunc

	// Retention
	retentionMaxAge  time.Duration
	retentionMaxRows uint64

	// summaryMu serialize writers of the summary_stats
	summaryMu sync.Mutex

	// dropped counts events discarded when the log buffer is full
	dropped     atomic.Uint64
	lastDropLog atomic.Int64
}

func NewDatabase(dbPath string, bufferSize int, batchSize int, flushFreq time.Duration) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Optimizing performance for high write throughput
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, fmt.Errorf("failed to execute pragma '%s': %w", p, err)
		}
	}

	// Single connection so the pragmas above apply to only connection in the pool
	db.SetMaxOpenConns(1)

	s := &Database{
		db:        db,
		logChan:   make(chan LogEvent, bufferSize),
		batchSize: batchSize,
		flushFreq: flushFreq,
	}

	if err := s.initSchema(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Database) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS traffic_logs (
	    id INTEGER PRIMARY KEY AUTOINCREMENT,
	    timestamp DATETIME NOT NULL,
	    protocol TEXT NOT NULL,
	    client_ip TEXT NOT NULL,
	    target TEXT NOT NULL,
	    action TEXT NOT NULL,
	    block_reason TEXT,
	    matched_by TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_timestamp ON traffic_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_action ON traffic_logs(action);

	CREATE TABLE IF NOT EXISTS summary_stats (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		total INTEGER NOT NULL DEFAULT 0,
		blocked INTEGER NOT NULL DEFAULT 0,
  		allowed INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS settings (
	    key TEXT PRIMARY KEY,
	    value TEXT NOT NULL,
	    updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS dynamic_domains (
	    domain TEXT PRIMARY KEY,
	    created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS dynamic_ips (
	    address TEXT PRIMARY KEY,
	    created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS allowlist_domains (
	    domain TEXT PRIMARY KEY,
	    created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS source_toggles (
	    id TEXT PRIMARY KEY,
	    active INTEGER NOT NULL,
	    updated_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS custom_sources (
	    id TEXT PRIMARY KEY,
	    name TEXT NOT NULL,
	    type TEXT NOT NULL,
	    url TEXT NOT NULL,
	    active INTEGER NOT NULL,
	    created_at TEXT NOT NULL
	);
	`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	//  To never lose the historical totals on an upgrade
	if _, err := s.db.Exec(`
	INSERT OR IGNORE INTO summary_stats (id, total, blocked, allowed)
	SELECT 1,
	       COALESCE(COUNT(*), 0),
	       COALESCE(SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END), 0),
	       COALESCE(SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END), 0)
	FROM traffic_logs;`); err != nil {
		return fmt.Errorf("failed to backfill summary: %w", err)
	}
	return nil
}

func (s *Database) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	s.wg.Add(1)
	go s.worker(ctx)
	if s.retentionMaxAge > 0 || s.retentionMaxRows > 0 {
		s.wg.Add(1)
		go s.purgeWorker(ctx)
	}
	log.Println("[STORAGE ENGINE] Asynchronous database logging started...")
}

func (s *Database) Log(event LogEvent) {
	select {
	case s.logChan <- event:
	default:
		n := s.dropped.Add(1)
		now := time.Now().UnixNano()
		last := s.lastDropLog.Load()
		if now-last >= int64(maxDropLogInterval) && s.lastDropLog.CompareAndSwap(last, now) {
			log.Printf("[WARNING] Log buffer is full: %d events dropped so far (preserved)", n)
		}
	}
}

func (s *Database) worker(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.flushFreq)
	defer ticker.Stop()

	batch := make([]LogEvent, 0, s.batchSize)

	for {
		select {
		case <-ctx.Done():
			s.flushBatch(batch)
			s.drainChannel()
			return

		case event, ok := <-s.logChan:
			if !ok {
				s.flushBatch(batch)
				return
			}
			batch = append(batch, event)
			if len(batch) >= s.batchSize {
				s.flushBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.flushBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *Database) flushBatch(batch []LogEvent) {
	if len(batch) == 0 {
		return
	}

	s.summaryMu.Lock()
	defer s.summaryMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("[ERROR] failed to start transaction: %v", err)
		return
	}

	stmt, err := tx.Prepare(`
			INSERT INTO traffic_logs (timestamp, protocol, client_ip, target, action, block_reason, matched_by)
			VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Printf("[ERROR] failed to prepare statement: %v", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	var total, blocked, allowed int64
	for _, e := range batch {
		// Store a canonical UTC timestamp
		_, err := stmt.Exec(e.Timestamp.UTC().Format(time.RFC3339Nano), e.Protocol, e.ClientIP, e.Target, e.Action, e.BlockReason, e.MatchedBy)
		if err != nil {
			log.Printf("[ERROR] failed to insert log statement: %v", err)
			continue
		}
		total++
		switch e.Action {
		case "BLOCK":
			blocked++
		case "ALLOW":
			allowed++
		}
	}
	if total > 0 {
		// Single row keeps summary instead of full table
		// scan on every dashboard load
		if _, err := tx.Exec(`
			INSERT INTO summary_stats (id, total, blocked, allowed)
			VALUES (1, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				total = summary_stats.total + excluded.total,
				blocked = summary_stats.blocked + excluded.blocked,
				allowed = summary_stats.allowed + excluded.allowed`,
			total, blocked, allowed); err != nil {
			log.Printf("[ERROR] failed to update summary: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[ERROR] failed to commit log transaction: %v", err)
	}
}

func (s *Database) drainChannel() {
	batch := make([]LogEvent, 0, s.batchSize)
	for {
		select {
		case event := <-s.logChan:
			batch = append(batch, event)
			if len(batch) >= s.batchSize {
				s.flushBatch(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				s.flushBatch(batch)
			}
			return
		}
	}
}

func (s *Database) GetSummary() (AnalyticsSummary, error) {
	var summary AnalyticsSummary
	err := s.db.QueryRow(`SELECT total, blocked, allowed FROM summary_stats WHERE id = 1`).
		Scan(&summary.TotalQueries, &summary.TotalBlocked, &summary.TotalAllowed)
	if err == sql.ErrNoRows {
		return summary, nil
	}
	if err != nil {
		return summary, fmt.Errorf("GetSummary: %w", err)
	}
	return summary, nil
}

// DropCount reports how many events were discrded
func (s *Database) DropCount() uint64 {
	return s.dropped.Load()
}

// SetRetention enables capping of traffic_logs
func (s *Database) SetRetention(maxAge time.Duration, maxRows uint64) {
	if maxAge < 0 {
		maxAge = 0
	}
	s.retentionMaxAge = maxAge
	s.retentionMaxRows = maxRows
}

// PurgeLogs enforces the configured retention.
func (s *Database) PurgeLogs() (int64, error) {
	var deleted int64

	if s.retentionMaxAge > 0 {
		cutoff := time.Now().Add(-s.retentionMaxAge).UTC().Format(time.RFC3339Nano)
		for {
			res, err := s.db.Exec(`
				DELETE FROM traffic_logs
				WHERE id IN (SELECT id FROM traffic_logs WHERE timestamp < ? LIMIT ?)`,
				cutoff, purgeChunk)
			if err != nil {
				return deleted, fmt.Errorf("PurgeLogs(age): %w", err)
			}
			n, _ := res.RowsAffected()
			deleted += n
			if n < purgeChunk {
				break
			}
		}
	}

	if s.retentionMaxRows > 0 {
		for {
			excess, err := s.excessRows()
			if err != nil {
				return deleted, err
			}
			if excess <= 0 {
				break
			}
			chunk := excess
			if chunk > purgeChunk {
				chunk = purgeChunk
			}
			res, err := s.db.Exec(`
				DELETE FROM traffic_logs
				WHERE id IN (SELECT id FROM traffic_logs ORDER BY id ASC LIMIT ?)`,
				chunk)
			if err != nil {
				return deleted, fmt.Errorf("PurgeLogs(rows): %w", err)
			}
			n, _ := res.RowsAffected()
			deleted += n
		}
	}

	if deleted > 0 {
		if err := s.resyncSummary(); err != nil {
			return deleted, err
		}
		log.Printf("[STORAGE ENGINE] retention purged %d traffic_logs rows", deleted)
	}

	return deleted, nil
}

func (s *Database) excessRows() (int64, error) {
	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM traffic_logs`).Scan(&total); err != nil {
		return 0, fmt.Errorf("PurgeLogs(count): %w", err)
	}
	if excess := total - int64(s.retentionMaxRows); excess > 0 {
		return excess, nil
	}
	return 0, nil
}

// resyncSummary recomputes the aggregate from the table
func (s *Database) resyncSummary() error {
	res, err := s.db.Exec(`
		UPDATE summary_stats SET
			total = (SELECT COALESCE(COUNT(*), 0) FROM traffic_logs),
			blocked = (SELECT COALESCE(SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END), 0) FROM traffic_logs),
			allowed = (SELECT COALESCE(SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END), 0) FROM traffic_logs)
		WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("resyncSummary: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// The singel row only exists after the first insert or backfill
		if _, err := s.db.Exec(`
			INSERT OR IGNORE INTO summary_stats (id, total, blocked, allowed)
			SELECT 1,
				COALESCE(COUNT(*), 0),
				COALESCE(SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END), 0)
			FROM traffic_logs`); err != nil {
			return fmt.Errorf("resyncSummary(insert): %w", err)
		}
	}
	return nil
}

// EraseLogs wipes the traffic logs, And resets the autoincrement sequence
func (s *Database) EraseLogs() (int64, error) {
	s.summaryMu.Lock()
	defer s.summaryMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("EraseLogs: Begin: %w", err)
	}

	res, err := tx.Exec(`DELETE FROM traffic_logs`)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("EraseLogs: Delete: %w", err)
	}
	deleted, _ := res.RowsAffected()

	if _, err := tx.Exec(`DELETE FROM sqlite_sequence WHERE name = 'traffic_logs'`); err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("EraseLogs: Reset Sequence: %w", err)
	}
	if _, err := tx.Exec(`UPDATE summary_stats SET total = 0, blocked = 0, allowed = 0 WHERE id = 1`); err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("EraseLogs: Reset Summary: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("EraseLogs: Commit: %w", err)
	}
	return deleted, nil
}

// purgeWorker applies retention periodically, It runs on its own goroutines
func (s *Database) purgeWorker(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(purgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.PurgeLogs(); err != nil {
				log.Printf("[STORAGE ENGINE] retention purge failed: %v", err)
			}
		}
	}
}

// QueryLogs returns persistent traffic logs rows newest first
func (s *Database) QueryLogs(limit, offset int, action string) ([]LogEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	q := `SELECT timestamp, protocol, client_ip, target, action, block_reason, matched_by
	      FROM traffic_logs`
	args := []any{}
	if action != "" {
		q += ` WHERE action = ?`
		args = append(args, action)
	}
	q += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("QueryLogs: %w", err)
	}
	defer rows.Close()

	var out []LogEvent
	for rows.Next() {
		var e LogEvent
		var ts string
		var reason, matched sql.NullString
		if err := rows.Scan(&ts, &e.Protocol, &e.ClientIP, &e.Target, &e.Action, &reason, &matched); err != nil {
			return nil, fmt.Errorf("QueryLogs scan: %w", err)
		}
		e.Timestamp = parseDBTime(ts)
		e.BlockReason = reason.String
		e.MatchedBy = matched.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// parseDBTime accepts the timestamp encodings (RFC3339nano)
func parseDBTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t
	}
	return time.Time{}
}

func (s *Database) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	return s.db.Close()
}

// GetSetting returns the values of a persisted setting.
func (s *Database) GetSetting(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("GetSetting(%s): %w", key, err)
	}
	return value, true, nil
}

// SetSettings upserts a setting by key
func (s *Database) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("SetSetting(%s): %w", key, err)
	}
	return nil
}

// AllSettings returns every persisted setting
func (s *Database) AllSettings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("AllSettings: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// ListDynamicDomains returns all persisted runtime blocklist domains
func (s *Database) ListDynamicDomains() ([]string, error) {
	rows, err := s.db.Query(`SELECT domain FROM dynamic_domains ORDER BY created_at, domain`)
	if err != nil {
		return nil, fmt.Errorf("ListDynamicDomains: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddDynamicDomain persists a runtime blocklist entrty
func (s *Database) AddDynamicDomain(domain string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO dynamic_domains (domain, created_at) VALUES (?, ?)`,
		domain, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("AddDynamicDomain(%s): %w", domain, err)
	}
	return nil
}

// RemoveDynamicDomain removes a persisted runtime blocklist entry
func (s *Database) RemoveDynamicDomain(domain string) error {
	_, err := s.db.Exec(`DELETE FROM dynamic_domains WHERE domain = ?`, domain)
	if err != nil {
		return fmt.Errorf("RemoveDynamicDomain(%s): %w", domain, err)
	}
	return nil
}

// ListDyanmicIPs returns all persisted runtime IP/CIDR blocklist entries
func (s *Database) ListDynamicIPs() ([]string, error) {
	rows, err := s.db.Query(`SELECT address FROM dynamic_ips ORDER BY created_at, address`)
	if err != nil {
		return nil, fmt.Errorf("ListDynamicIPs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AddDynamicIP persists a runtime IP/CIDR blocklist entry
func (s *Database) AddDynamicIP(address string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO dynamic_ips (address, created_at) VALUES (?, ?)`,
		address, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("AddDynamicIP(%s): %w", address, err)
	}
	return nil
}

// RemoveDynamicIP removes a persisted runtime IP/CIDR blocklist entry
func (s *Database) RemoveDynamicIP(address string) error {
	_, err := s.db.Exec(`DELETE FROM dynamic_ips WHERE address = ?`, address)
	if err != nil {
		return fmt.Errorf("RemoveDynamicIP(%s): %w", address, err)
	}
	return nil
}

// ListAllowlistDomains return all persisted allowlist entries
func (s *Database) ListAllowlistDomains() ([]string, error) {
	rows, err := s.db.Query(`SELECT domain FROM allowlist_domains ORDER BY created_at, domain`)
	if err != nil {
		return nil, fmt.Errorf("ListAllowlistDomains: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddAllowlistDomain persists an allowlist entry
func (s *Database) AddAllowlistDomain(domain string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO allowlist_domains (domain, created_at) VALUES (?, ?)`,
		domain, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("AddAllowlistDomain(%s): %w", domain, err)
	}
	return nil
}

// RemoveAllowlistDomain removes a persisted allowlist entry
func (s *Database) RemoveAllowlistDomain(domain string) error {
	_, err := s.db.Exec(`DELETE FROM allowlist_domains WHERE domain = ?`, domain)
	if err != nil {
		return fmt.Errorf("RemoveAllowlistDomain(%s): %w", domain, err)
	}
	return nil
}

// ListSourceToggles returns the persisted Active state of blocklist sources
func (s *Database) ListSourceToggles() (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT id, active FROM source_toggles`)
	if err != nil {
		return nil, fmt.Errorf("ListSourceToggles: %w", err)
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var id string
		var active int
		if err := rows.Scan(&id, &active); err != nil {
			return nil, err
		}
		out[id] = active != 0
	}
	return out, rows.Err()
}

// SaveSourceToggle persists a sources Active state
func (s *Database) SaveSourceToggle(id string, active bool) error {
	val := 0
	if active {
		val = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO source_toggles (id, active, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET active = excluded.active, updated_at = excluded.updated_at`,
		id, val, time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("SaveSourceToggle(%s): %w", id, err)
	}
	return nil
}

// ListCustomSources returns all persisted runtime added sources
func (s *Database) ListCustomSources() ([]CustomSource, error) {
	rows, err := s.db.Query(`SELECT id, name, type, url, active, created_at FROM custom_sources ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("ListCustomSources: %w", err)
	}
	defer rows.Close()
	var out []CustomSource
	for rows.Next() {
		var c CustomSource
		var active int
		var created string
		if err := rows.Scan(&c.ID, &c.Name, &c.Type, &c.URL, &active, &created); err != nil {
			return nil, err
		}
		c.Active = active != 0
		if t, err := time.Parse(time.RFC3339, created); err == nil {
			c.CreatedAt = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveCustomSources upserts a runtime added sources
func (s *Database) SaveCustomSource(c CustomSource) error {
	val := 0
	if c.Active {
		val = 1
	}
	created := c.CreatedAt.Format(time.RFC3339)
	if c.CreatedAt.IsZero() {
		created = time.Now().Format(time.RFC3339)
	}
	_, err := s.db.Exec(
		`INSERT INTO custom_sources (id, name, type, url, active, created_at) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		    name = excluded.name, type = excluded.type, url = excluded.url,
		    active = excluded.active, created_at = excluded.created_at`,
		c.ID, c.Name, c.Type, c.URL, val, created,
	)
	if err != nil {
		return fmt.Errorf("SaveCustomSource(%s): %w", c.ID, err)
	}
	return nil
}
