package tessera

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	logformat "github.com/transparency-dev/formats/log"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/client"
	"github.com/transparency-dev/trillian-tessera/storage/mysql"
)

type dbConfig struct {
	baseURI           string
	dbConnMaxLifetime time.Duration
	dbMaxOpenConns    int
	dbMaxIdleConns    int
}

func NewDBConfig(baseURI string, dbConnMaxLifetime time.Duration, dbMaxOpenConns, dbMaxIdleConns int) dbConfig {
	return dbConfig{
		baseURI:           baseURI,
		dbConnMaxLifetime: dbConnMaxLifetime,
		dbMaxOpenConns:    dbMaxOpenConns,
		dbMaxIdleConns:    dbMaxIdleConns,
	}
}

func (d *dbConfig) Connect(dbName string) (*sql.DB, error) {
	uri := d.baseURI + "/" + dbName
	db, err := sql.Open("mysql", uri)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(d.dbConnMaxLifetime)
	db.SetMaxOpenConns(d.dbMaxOpenConns)
	db.SetMaxIdleConns(d.dbMaxIdleConns)

	return db, nil
}

type batchOptions struct {
	maxAge  time.Duration
	maxSize uint
}

type TesseraClient struct {
	dbConfig     *dbConfig
	batchOptions batchOptions
}

func NewTesseraClient(dbConfig *dbConfig, maxAge time.Duration, maxSize uint) TesseraClient {
	return TesseraClient{
		dbConfig: dbConfig,
		batchOptions: batchOptions{
			maxAge:  maxAge,
			maxSize: maxSize,
		},
	}
}

type noopSigner struct{}

func (n noopSigner) Name() string                    { return "noop" }
func (n noopSigner) KeyHash() uint32                 { return 1 }
func (n noopSigner) Sign(msg []byte) ([]byte, error) { return msg, nil }

func (t *TesseraClient) Connect(ctx context.Context, treeID string) (*mysql.Storage, error) {
	db, err := t.dbConfig.Connect(treeID)
	if err != nil {
		return nil, fmt.Errorf("database connection: %w", err)
	}
	// Rekor signs the checkpoints itself, no need to create a separate checkpoint signer for Tessera
	signer := noopSigner{}
	storage, err := mysql.New(ctx, db, tessera.WithCheckpointSigner(signer), tessera.WithBatching(t.batchOptions.maxSize, t.batchOptions.maxAge))
	if err != nil {
		return nil, fmt.Errorf("tessera client connection: %w", err)
	}
	return storage, nil
}

func ProofBuilder(ctx context.Context, checkpoint logformat.Checkpoint, tesseraStorage *mysql.Storage) (*client.ProofBuilder, error) {
	proofBuilder, err := client.NewProofBuilder(ctx, checkpoint, tesseraStorage.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("new proof builder: %w", err)
	}
	return proofBuilder, nil
}

func GetLatestCheckpoint(ctx context.Context, tesseraStorage *mysql.Storage) (logformat.Checkpoint, error) {
	checkpointBody, err := tesseraStorage.ReadCheckpoint(ctx)
	if err != nil {
		return logformat.Checkpoint{}, err
	}
	if checkpointBody == nil {
		return logformat.Checkpoint{}, fmt.Errorf("checkpoint not found")
	}
	checkpoint := logformat.Checkpoint{}
	_, err = checkpoint.Unmarshal(checkpointBody)
	if err != nil {
		return logformat.Checkpoint{}, err
	}
	return checkpoint, nil
}
