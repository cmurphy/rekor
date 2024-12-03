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
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/spf13/viper"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pubsub"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/tessera"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	_ "github.com/sigstore/rekor/pkg/pubsub/gcp" // Load GCP pubsub implementation
)

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
	tesseraClient := tessera.NewTesseraClient(&cfg, viper.GetDuration("tessera.batch_max_age"), viper.GetUint("tessera.batch_max_size"))

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
	api *API
)

func ConfigureAPI() {
	var err error

	api, err = NewAPI()
	if err != nil {
		log.Logger.Panic(err)
	}
}

func StopAPI() {
	api.checkpointPublishCancel()

	if api.newEntryPublisher != nil {
		if err := api.newEntryPublisher.Close(); err != nil {
			log.Logger.Errorf("shutting down newEntryPublisher: %v", err)
		}
	}
}
