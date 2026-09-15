package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"
)

// LogEvent represents a single traffic event for logging in database
type LogEvent struct {
	Timestamp   time.Time
	Protocol    string // DNS or TLS
	ClientIP    string
	Target      string // Domain or SNI
	Action      string // Allowed or Blocked
	BlockReason string
	MatchedBy   string
}

// AnalyticsSummary Contains metrics for dashboard display
type AnalyticsSummary struct {
	TotalQueries int64 `json:"total_queries"`
	TotalBlocked int64 `json:"total_blocked"`
	TotalAllowed int64 `json:"total_allowed"`
}

// Database Intialization
type Database struct {
	db        *sql.DB
	logChan   chan LogEvent
	batchSize int
	flushFreq time.Duration
	wg        sync.WaitGroup
	cancel    context.CancelFunc
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
	`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}
	return nil
}

func (s *Database) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	s.wg.Add(1)
	go s.worker(ctx)
	log.Println("[STORAGE ENGINE] Asynchronous database logging started...")
}

func (s *Database) Log(event LogEvent) {
	select {
	case s.logChan <- event:
	default:
		log.Println("[WARNING] Log buffer is full! Dropping log events to preserve network throughput.")
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
				batch = make([]LogEvent, 0, s.batchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.flushBatch(batch)
				batch = make([]LogEvent, 0, s.batchSize)
			}
		}
	}
}

func (s *Database) flushBatch(batch []LogEvent) {
	if len(batch) == 0 {
		return
	}

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

	for _, e := range batch {
		_, err := stmt.Exec(e.Timestamp, e.Protocol, e.ClientIP, e.Target, e.Action, e.BlockReason, e.MatchedBy)
		if err != nil {
			log.Printf("[ERROR] failed to insert log statement: %v", err)
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
				batch = make([]LogEvent, 0, s.batchSize)
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
	query := `
		SELECT 
				COUNT(*),
				SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END),
				SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END)
		FROM traffic_logs;
	`

	var blocked, allowed sql.NullInt64
	err := s.db.QueryRow(query).Scan(&summary.TotalQueries, &blocked, &allowed)
	if err != nil {
		return summary, err
	}
	summary.TotalBlocked = blocked.Int64
	summary.TotalAllowed = allowed.Int64
	return summary, nil
}

func (s *Database) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	return s.db.Close()
}
