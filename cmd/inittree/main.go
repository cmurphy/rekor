package main

import (
	"context"
	"database/sql"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/rekor/pkg/api"
	"github.com/sigstore/rekor/pkg/log"
	"sigs.k8s.io/release-utils/version"
)

//go:embed schema.sql
var schema string

var (
	treeID         = flag.String("tessera_treeid", "", "Tessera tree ID")
	storageBackend = flag.String("tessera_storage", "posix", "Tessera storage backend, one of posix, mysql")
	posixDir       = flag.String("tessera.posix.storage_dir", "", "Tessera POSIX root directory")
	mysqlAddress   = flag.String("tessera.mysql.address", "127.0.0.1", "Tessera MySQL server address")
	mysqlPort      = flag.Uint("tessera.mysql.port", 3306, "Tessera MySQL server port")
	mysqlUser      = flag.String("tessera.mysql.user", "", "Tessera MySQL server username")
	mysqlPassword  = flag.String("tessera.mysql.password", "", "Tessera MySQL server password")
	timeout        = flag.Duration("timeout", 0*time.Second, "Maximum time to wait before aborting connection")
	versionFlag    = flag.Bool("version", false, "Print the current version of inittree")
)

func main() {
	flag.Parse()

	versionInfo := version.GetVersionInfo()
	if *versionFlag {
		fmt.Println(versionInfo.String())
		os.Exit(0)
	}

	ctx := context.Background()
	if *timeout > 0*time.Second {
		ctx, _ = context.WithTimeout(ctx, *timeout)
	}

	if *treeID == "" {
		log.Logger.Fatal("must set --tessera_treeid to initialize the tree")
	}

	var err error
	switch *storageBackend {
	case "mysql":
		err = setupMySQL(ctx)
	case "posix":
		if *posixDir == "" {
			log.Logger.Fatal("must set --tessera.posix.storage_dir for posix storage")
		}
		err = setupPOSIX(ctx)
	default:
		log.Logger.Fatal("must set --tessera_storage to one of posix, mysql")
	}
	if err != nil {
		log.Logger.Fatal(err)
	}
}

func setupMySQL(ctx context.Context) error {
	log.Logger.Infof("Initializing database schema")

	uri := api.MySQLURI(*mysqlAddress, *mysqlUser, *mysqlPassword, uint16(*mysqlPort))
	uri = fmt.Sprintf("%s/", uri)
	conn, err := sql.Open("mysql", uri)
	if err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS "+*treeID)
	if err != nil {
		return err
	}
	if conn.Close(); err != nil {
		return err
	}
	dbURI := fmt.Sprintf("%s%s?multiStatements=true", uri, *treeID)
	db, err := sql.Open("mysql", dbURI)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Logger.Warnf("Failed to close db: %v", err)
		}
	}()

	if _, err := db.ExecContext(ctx, schema); err != nil {
		return err
	}

	log.Logger.Info("Database schema initialized")
	return nil
}

func setupPOSIX(ctx context.Context) error {
	log.Logger.Infof("Initializing directory")

	if err := os.MkdirAll(filepath.Join(*posixDir, *treeID), 0o755); err != nil {
		return err
	}

	log.Logger.Info("Directory initialized")
	return nil
}
