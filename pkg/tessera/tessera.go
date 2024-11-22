package tessera

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/spf13/viper"
	logformat "github.com/transparency-dev/formats/log"
	tessera "github.com/transparency-dev/trillian-tessera"
	"github.com/transparency-dev/trillian-tessera/api/layout"
	"github.com/transparency-dev/trillian-tessera/client"
	"github.com/transparency-dev/trillian-tessera/storage/mysql"
)

//go:embed schema.sql
var schema string

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

func (d *dbConfig) Init(ctx context.Context, dbName string) error {
	log.Logger.Infof("Initializing database schema")
	uri := d.baseURI + "/" + dbName + "?multiStatements=true"
	db, err := sql.Open("mysql", uri)
	if err != nil {
		return fmt.Errorf("Failed to connect to DB: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Logger.Warnf("Failed to close db: %v", err)
		}
	}()

	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("Failed to execute init database schema: %w", err)
	}

	log.Logger.Info("Database schema initialized")
	return nil
}

type TesseraClient struct {
	dbConfig *dbConfig
}

func NewTesseraClient(dbConfig *dbConfig) TesseraClient {
	return TesseraClient{dbConfig}
}

func (t *TesseraClient) Connect(ctx context.Context, treeID string) (*mysql.Storage, error) {
	db, err := t.dbConfig.Connect(treeID)
	if err != nil {
		return nil, fmt.Errorf("database connection: %w", err)
	}
	// Rekor signs the checkpoints itself, no need to create a separate checkpoint signer for Tessera
	withNoopCP := func(o *tessera.StorageOptions) {
		o.NewCP = func(size uint64, hash []byte) ([]byte, error) {
			cp := logformat.Checkpoint{
				Origin: viper.GetString("rekor_server.hostname"),
				Size:   size,
				Hash:   hash,
			}.Marshal()
			return cp, nil
		}
		o.ParseCP = func(raw []byte) (*logformat.Checkpoint, error) {
			cp := &logformat.Checkpoint{}
			_, err := cp.Unmarshal(raw)
			return cp, err
		}
	}
	storage, err := mysql.New(ctx, db, withNoopCP)
	if err != nil {
		return nil, fmt.Errorf("tessera client connection: %w", err)
	}
	return storage, nil
}

func ProofBuilder(ctx context.Context, checkpoint logformat.Checkpoint, tesseraStorage *mysql.Storage) (*client.ProofBuilder, error) {
	tileOnlyFetcher := func(ctx context.Context, path string) ([]byte, error) {
		pathParts := strings.SplitN(path, "/", 3)
		level, index, width, err := layout.ParseTileLevelIndexWidth(pathParts[1], pathParts[2])
		if err != nil {
			return nil, err
		}
		return tesseraStorage.ReadTile(ctx, level, index, width)
	}
	proofBuilder, err := client.NewProofBuilder(ctx, checkpoint, tileOnlyFetcher)
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
