package api

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/rekor/pkg/log"
	"golang.org/x/mod/sumdb/note"
)

func createDatabase(ctx context.Context, mysqlURI string, dbConnMaxLifetime time.Duration, dbMaxOpenConns, dbMaxIdleConns int) (*sql.DB, error) {
	db, err := sql.Open("mysql", mysqlURI)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(dbConnMaxLifetime)
	db.SetMaxOpenConns(dbMaxOpenConns)
	db.SetMaxIdleConns(dbMaxIdleConns)

	err = initDatabaseSchema(ctx, mysqlURI)
	return db, err
}

func initDatabaseSchema(ctx context.Context, mysqlURI string) error {
	log.Logger.Infof("Initializing database schema")

	db, err := sql.Open("mysql", mysqlURI+"?multiStatements=true")
	if err != nil {
		return fmt.Errorf("Failed to connect to DB: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Logger.Warnf("Failed to close db: %v", err)
		}
	}()

	initSchemaPath := "/home/colleenmurphy/dev/trillian-tessera/storage/mysql/schema.sql" // FIXME: copy into rekor source
	rawSchema, err := os.ReadFile(initSchemaPath)
	if err != nil {
		return fmt.Errorf("Failed to read init schema file %q: %w", initSchemaPath, err)
	}
	if _, err := db.ExecContext(ctx, string(rawSchema)); err != nil {
		return fmt.Errorf("Failed to execute init database schema: %w", err)
	}

	log.Logger.Info("Database schema initialized")
	return nil
}

func createSigner(privateKeyPath string) (note.Signer, error) {
	rawPrivateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private key file %q: %w", privateKeyPath, err)
	}
	noteSigner, err := note.NewSigner(string(rawPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("Failed to create new signer: %w", err)
	}
	return noteSigner, nil
}

func createVerifier(publicKeyPath string) (string, note.Verifier, error) {
	rawPublicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to read public key file %q: %w", publicKeyPath, err)
	}
	noteVerifier, err := note.NewVerifier(string(rawPublicKey))
	if err != nil {
		return "", nil, fmt.Errorf("Failed to create new verifier: %w", err)
	}
	return string(rawPublicKey), noteVerifier, nil
}
