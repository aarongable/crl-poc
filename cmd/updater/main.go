package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"io"
	"math/big"
	mrand "math/rand"
	"os"
	"time"

	"github.com/honeycombio/beeline-go"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"

	crlpb "github.com/aarongable/crl-poc/generator/proto"
)

type Config struct {
	Updater struct {
		cmd.ServiceConfig

		CRLGeneratorService *cmd.GRPCClientConfig

		// Issuers is a list of all issuers which can sign CRLs.
		Issuers []issuance.IssuerConfig

		Features map[string]bool
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.Updater.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	tlsConfig, err := c.Updater.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.Updater.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	clk := cmd.Clock()

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	// Set up the proof-of-concept gRPC client.
	issuers := make([]*issuance.Issuer, 0, len(c.Updater.Issuers))
	for _, issuerConfig := range c.Updater.Issuers {
		cert, signer, err := issuance.LoadIssuer(issuerConfig.Location)
		cmd.FailOnError(err, "Failed to load issuer")
		issuers = append(issuers, &issuance.Issuer{Cert: cert, Signer: signer})
	}

	clientMetrics := bgrpc.NewClientMetrics(scope)

	conn, err := bgrpc.ClientSetup(c.Updater.CRLGeneratorService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CRLGenerator")
	cc := crlpb.NewCRLGeneratorClient(conn)

	// Make a call to see if it works! Stream a bunch of random serials and
	// statuses across, then read all the bytes back. Not using a goroutine
	// because we know the server side is synchronous and won't start sending
	// responses until the input stream is complete.
	numShards := 100
	for i := 0; i < numShards; i++ {
		start := time.Now()
		stream, err := cc.GenerateCRL(context.Background())
		cmd.FailOnError(err, "Failed to create gRPC stream")

		err = stream.Send(&crlpb.GenerateCRLRequest{
			Payload: &crlpb.GenerateCRLRequest_Metadata{
				Metadata: &crlpb.CRLMetadata{
					IssuerNameID: int64(issuers[0].Cert.NameID()),
					ThisUpdate:   clk.Now().UnixNano(),
				},
			},
		})
		cmd.FailOnError(err, "Failed to send metadata")

		numEntries := 100_000
		for j := 0; j < numEntries; j++ {
			var serialBytes [16]byte
			_, _ = rand.Read(serialBytes[:])
			serial := big.NewInt(0).SetBytes(serialBytes[:])
			serialString := core.SerialToString(serial)

			reason := int32(mrand.Intn(10))

			ninetyDays := time.Duration(90 * 24 * time.Hour)
			earliest := clk.Now().Add(-ninetyDays).UnixNano()
			revokedAt := time.Unix(0, earliest+mrand.Int63n(ninetyDays.Nanoseconds())).UnixNano()

			err = stream.Send(&crlpb.GenerateCRLRequest{
				Payload: &crlpb.GenerateCRLRequest_Entry{
					Entry: &crlpb.CRLEntry{
						Serial:    serialString,
						Reason:    reason,
						RevokedAt: revokedAt,
					},
				},
			})
			cmd.FailOnError(err, "Failed to send crl entry")
		}
		err = stream.CloseSend()
		cmd.FailOnError(err, "Failed to close send stream")

		crlBytes := make([]byte, 0)
		for {
			out, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				cmd.FailOnError(err, "Failed to read from response stream")
			}

			crlBytes = append(crlBytes, out.Chunk...)
		}

		crl, err := x509.ParseDERCRL(crlBytes)
		cmd.FailOnError(err, "Failed to parse CRL bytes")

		err = issuers[0].Cert.CheckCRLSignature(crl)
		cmd.FailOnError(err, "Failed to validate CRL signature")

		if len(crl.TBSCertList.RevokedCertificates) != numEntries {
			cmd.Fail("Got wrong number of entries back in CRL")
		}

		elapsed := time.Since(start)
		logger.Warningf("Shard %03d took %02.02fs", i, elapsed.Seconds())
	}
}
