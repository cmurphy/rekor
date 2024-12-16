package tessera

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	logformat "github.com/transparency-dev/formats/log"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"github.com/transparency-dev/trillian-tessera/client"
	"github.com/transparency-dev/trillian-tessera/storage/mysql"
	"github.com/transparency-dev/trillian-tessera/storage/posix"
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

type fileConfig struct {
	storageDir string
}

func NewFileConfig(storageDir string) fileConfig {
	return fileConfig{storageDir}
}

func (f *fileConfig) Validate(treeID string) error {
	_, err := os.Stat(filepath.Join(f.storageDir, treeID))
	if err != nil {
		return fmt.Errorf("storage directory was invalid: %w", err)
	}
	return nil
}

type batchOptions struct {
	maxAge  time.Duration
	maxSize uint
}

type TesseraClient struct {
	fileConfig   *fileConfig
	dbConfig     *dbConfig
	batchOptions batchOptions
}

type Option func(*TesseraClient)

func WithPosix(f *fileConfig) Option {
	return func(c *TesseraClient) {
		c.fileConfig = f
	}
}

func WithMySQL(d *dbConfig) Option {
	return func(c *TesseraClient) {
		c.dbConfig = d
	}
}

func NewTesseraClient(maxAge time.Duration, maxSize uint, storageOption Option) *TesseraClient {
	c := &TesseraClient{
		batchOptions: batchOptions{
			maxAge:  maxAge,
			maxSize: maxSize,
		},
	}
	storageOption(c)
	return c
}

type TesseraStorage struct {
	Add             func(context.Context, *tessera.Entry) tessera.IndexFuture
	ReadCheckpoint  client.CheckpointFetcherFunc
	ReadTile        client.TileFetcherFunc
	ReadEntryBundle client.EntryBundleFetcherFunc
}

type noopSigner struct{}

func (n noopSigner) Name() string                    { return "noop" }
func (n noopSigner) KeyHash() uint32                 { return 1 }
func (n noopSigner) Sign(msg []byte) ([]byte, error) { return msg, nil }

func (t *TesseraClient) Connect(ctx context.Context, treeID string) (*TesseraStorage, error) {
	// Rekor signs the checkpoints itself, no need to create a separate checkpoint signer for Tessera
	signer := noopSigner{}
	switch {
	case t.fileConfig != nil:
		err := t.fileConfig.Validate(treeID)
		if err != nil {
			return nil, fmt.Errorf("filesystem validation error: %w", err)
		}
		initialize := false
		if _, err := os.Stat(filepath.Join(t.fileConfig.storageDir, treeID, layout.CheckpointPath)); os.IsNotExist(err) {
			initialize = true
		}
		storage, err := posix.New(ctx, filepath.Join(t.fileConfig.storageDir, treeID), initialize, tessera.WithCheckpointSigner(signer), tessera.WithBatching(t.batchOptions.maxSize, t.batchOptions.maxAge))
		if err != nil {
			return nil, fmt.Errorf("tessera client connection: %w", err)
		}
		return &TesseraStorage{
			Add:             storage.Add,
			ReadCheckpoint:  storage.ReadCheckpoint,
			ReadTile:        storage.ReadTile,
			ReadEntryBundle: storage.ReadEntryBundle,
		}, nil
	case t.dbConfig != nil:
		db, err := t.dbConfig.Connect(treeID)
		if err != nil {
			return nil, fmt.Errorf("database connection: %w", err)
		}
		storage, err := mysql.New(ctx, db, tessera.WithCheckpointSigner(signer), tessera.WithBatching(t.batchOptions.maxSize, t.batchOptions.maxAge))
		if err != nil {
			return nil, fmt.Errorf("tessera client connection: %w", err)
		}
		return &TesseraStorage{
			Add:             storage.Add,
			ReadCheckpoint:  storage.ReadCheckpoint,
			ReadTile:        storage.ReadTile,
			ReadEntryBundle: storage.ReadEntryBundle,
		}, nil
	default:
		return nil, fmt.Errorf("invalid storage configuration")
	}
}

func ProofBuilder(ctx context.Context, checkpoint logformat.Checkpoint, tesseraStorage *TesseraStorage) (*client.ProofBuilder, error) {
	proofBuilder, err := client.NewProofBuilder(ctx, checkpoint, tesseraStorage.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("new proof builder: %w", err)
	}
	return proofBuilder, nil
}

func GetLatestCheckpoint(ctx context.Context, tesseraStorage *TesseraStorage) (logformat.Checkpoint, error) {
	checkpointBody, err := tesseraStorage.ReadCheckpoint(ctx)
	if err != nil {
		return logformat.Checkpoint{}, err
	}
	if checkpointBody == nil {
		return logformat.Checkpoint{}, fmt.Errorf("checkpoint not found")
	}
	return UnmarshalCheckpoint(checkpointBody)
}

func UnmarshalCheckpoint(checkpointBody []byte) (logformat.Checkpoint, error) {
	checkpoint := logformat.Checkpoint{}
	_, err := checkpoint.Unmarshal(checkpointBody)
	return checkpoint, err
}
