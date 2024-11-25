//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pubsub"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/tessera"
	"github.com/sigstore/rekor/pkg/witness"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	_ "github.com/sigstore/rekor/pkg/pubsub/gcp" // Load GCP pubsub implementation
)

func dial(rpcServer string) (*grpc.ClientConn, error) {
	// Extract the hostname without the port
	hostname := rpcServer
	if idx := strings.Index(rpcServer, ":"); idx != -1 {
		hostname = rpcServer[:idx]
	}
	// Set up and test connection to rpc server
	var creds credentials.TransportCredentials
	tlsCACertFile := viper.GetString("trillian_log_server.tls_ca_cert")
	useSystemTrustStore := viper.GetBool("trillian_log_server.tls")

	switch {
	case useSystemTrustStore:
		creds = credentials.NewTLS(&tls.Config{
			ServerName: hostname,
			MinVersion: tls.VersionTLS12,
		})
	case tlsCACertFile != "":
		tlsCaCert, err := os.ReadFile(filepath.Clean(tlsCACertFile))
		if err != nil {
			log.Logger.Fatalf("Failed to load tls_ca_cert:", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(tlsCaCert) {
			return nil, fmt.Errorf("failed to append CA certificate to pool")
		}
		creds = credentials.NewTLS(&tls.Config{
			ServerName: hostname,
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		})
	default:
		creds = insecure.NewCredentials()
	}
	conn, err := grpc.NewClient(rpcServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Logger.Fatalf("Failed to connect to RPC server:", err)
	}

	return conn, nil
}

type API struct {
	tesseraClient *tessera.TesseraClient
	pubkey        string // PEM encoded public key
	pubkeyHash    string // SHA256 hash of DER-encoded public key
	signer        signature.Signer
	// stops checkpoint publishing
	checkpointPublishCancel context.CancelFunc
	// Publishes notifications when new entries are added to the log. May be
	// nil if no publisher is configured.
	newEntryPublisher pubsub.Publisher
}

func MySQLURI(address, user, pass string, port uint16) string {
	uri := fmt.Sprintf("tcp(%s:%d)", address, port)
	if pass != "" {
		pass = fmt.Sprintf(":%s", pass)
	}
	if user != "" {
		uri = fmt.Sprintf("%s%s@%s", user, pass, uri)
	}
	return uri
}

func NewAPI() (*API, error) {
	ctx := context.Background()

	uri := MySQLURI(
		viper.GetString("tessera.mysql.address"),
		viper.GetString("tessera.mysql.user"),
		viper.GetString("tessera.mysql.password"),
		viper.GetUint16("tessera.mysql.port"),
	)
	lifetime, maxOpen, maxIdle := viper.GetDuration("tessera.mysql.conn_max_lifetime"), viper.GetInt("tessera.mysql.max_open_connections"), viper.GetInt("tessera.mysql.max_idle_connections")
	cfg := tessera.NewDBConfig(uri, lifetime, maxOpen, maxIdle)
	tesseraClient := tessera.NewTesseraClient(&cfg)

	log.Logger.Infof("Starting Rekor server")

	rekorSigner, err := signer.New(ctx, viper.GetString("rekor_server.signer"),
		viper.GetString("rekor_server.signer-passwd"))
	if err != nil {
		return nil, fmt.Errorf("getting new signer: %w", err)
	}
	pk, err := rekorSigner.PublicKey(options.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}
	b, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key: %w", err)
	}
	pubkeyHashBytes := sha256.Sum256(b)

	pubkey := cryptoutils.PEMEncode(cryptoutils.PublicKeyPEMType, b)

	var newEntryPublisher pubsub.Publisher
	if p := viper.GetString("rekor_server.new_entry_publisher"); p != "" {
		if !viper.GetBool("rekor_server.publish_events_protobuf") && !viper.GetBool("rekor_server.publish_events_json") {
			return nil, fmt.Errorf("%q is configured but neither %q or %q are enabled", "new_entry_publisher", "publish_events_protobuf", "publish_events_json")
		}
		newEntryPublisher, err = pubsub.Get(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("init event publisher: %w", err)
		}
		log.ContextLogger(ctx).Infof("Initialized new entry event publisher: %s", p)
	}

	return &API{
		// Transparency Log Stuff
		tesseraClient: &tesseraClient,
		// Signing/verifying fields
		pubkey:     string(pubkey),
		pubkeyHash: hex.EncodeToString(pubkeyHashBytes[:]),
		signer:     rekorSigner,
		// Utility functionality not required for operation of the core service
		newEntryPublisher: newEntryPublisher,
	}, nil
}

var (
	api         *API
	redisClient *redis.Client
)

func ConfigureAPI() {
	var err error

	api, err = NewAPI()
	if err != nil {
		log.Logger.Panic(err)
	}

	if viper.GetBool("enable_stable_checkpoint") {
		redisClient = NewRedisClient()
		checkpointPublisher := witness.NewCheckpointPublisher(context.Background(), api.tesseraClient, 0,
			viper.GetString("rekor_server.hostname"), api.signer, redisClient, viper.GetUint("publish_frequency"), CheckpointPublishCount)

		// create context to cancel goroutine on server shutdown
		ctx, cancel := context.WithCancel(context.Background())
		api.checkpointPublishCancel = cancel
		checkpointPublisher.StartPublisher(ctx)
	}
}

func NewRedisClient() *redis.Client {

	opts := &redis.Options{
		Addr:     fmt.Sprintf("%v:%v", viper.GetString("redis_server.address"), viper.GetUint64("redis_server.port")),
		Password: viper.GetString("redis_server.password"),
		Network:  "tcp",
		DB:       0, // default DB
	}

	// #nosec G402
	if viper.GetBool("redis_server.enable-tls") {
		opts.TLSConfig = &tls.Config{
			InsecureSkipVerify: viper.GetBool("redis_server.insecure-skip-verify"), //nolint: gosec
		}
	}

	return redis.NewClient(opts)
}

func StopAPI() {
	api.checkpointPublishCancel()

	if api.newEntryPublisher != nil {
		if err := api.newEntryPublisher.Close(); err != nil {
			log.Logger.Errorf("shutting down newEntryPublisher: %v", err)
		}
	}
}
