package main

import (
	"context"
	"database/sql"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/rekor/pkg/api"
	"github.com/sigstore/rekor/pkg/log"
	"sigs.k8s.io/release-utils/version"
)

//go:embed schema.sql
var schema string

var (
	mysqlAddress  = flag.String("tessera.mysql.address", "127.0.0.1", "Tessera MySQL server address")
	mysqlPort     = flag.Uint("tessera.mysql.port", 3306, "Tessera MySQL server port")
	mysqlUser     = flag.String("tessera.mysql.user", "", "Tessera MySQL server username")
	mysqlPassword = flag.String("tessera.mysql.password", "", "Tessera MySQL server password")
	treeID        = flag.String("tessera.treeid", "", "Tessera tree ID")
	timeout       = flag.Duration("timeout", 0*time.Second, "Maximum time to wait before aborting connection")
	versionFlag   = flag.Bool("version", false, "Print the current version of inittree")
)

func main() {
	flag.Parse()

	versionInfo := version.GetVersionInfo()
	if *versionFlag {
		fmt.Println(versionInfo.String())
		os.Exit(0)
	}

	log.Logger.Infof("Initializing database schema")

	ctx := context.Background()
	if *timeout > 0*time.Second {
		ctx, _ = context.WithTimeout(ctx, *timeout)
	}

	uri := api.MySQLURI(*mysqlAddress, *mysqlUser, *mysqlPassword, uint16(*mysqlPort))
	uri = fmt.Sprintf("%s/", uri)
	conn, err := sql.Open("mysql", uri)
	if err != nil {
		log.Logger.Fatal(err)
	}
	_, err = conn.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS "+*treeID)
	if err != nil {
		log.Logger.Fatal(err)
	}
	if conn.Close(); err != nil {
		log.Logger.Fatal(err)
	}
	dbURI := fmt.Sprintf("%s%s?multiStatements=true", uri, *treeID)
	db, err := sql.Open("mysql", dbURI)
	if err != nil {
		log.Logger.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Logger.Warnf("Failed to close db: %v", err)
		}
	}()

	if _, err := db.ExecContext(ctx, schema); err != nil {
		log.Logger.Fatal(err)
	}

	log.Logger.Info("Database schema initialized")
}
