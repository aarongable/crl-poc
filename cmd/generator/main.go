package main

import (
	"flag"
	"os"

	"github.com/honeycombio/beeline-go"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"

	"github.com/aarongable/crl-poc/generator"
	crlpb "github.com/aarongable/crl-poc/generator/proto"
)

type Config struct {
	Generator struct {
		cmd.ServiceConfig

		GRPCCRLGenerator *cmd.GRPCServerConfig

		// Issuers is a list of all issuers which can sign CRLs.
		Issuers []issuance.IssuerConfig

		// LifespanCRL is how long CRLs are valid for. Per the BRs, Section 4.9.7,
		// it MUST NOT be more than 10 days.
		LifespanCRL cmd.ConfigDuration

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

	err = features.Set(c.Generator.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	tlsConfig, err := c.Generator.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.Generator.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	clk := cmd.Clock()

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	// Set up the proof-of-concept gRPC server.
	issuers := make([]*issuance.Issuer, 0, len(c.Generator.Issuers))
	for _, issuerConfig := range c.Generator.Issuers {
		cert, signer, err := issuance.LoadIssuer(issuerConfig.Location)
		cmd.FailOnError(err, "Failed to load issuer")
		issuers = append(issuers, &issuance.Issuer{Cert: cert, Signer: signer})
	}

	ci, err := generator.NewGeneratorImpl(issuers, c.Generator.LifespanCRL.Duration, logger)
	cmd.FailOnError(err, "Failed to create CRL impl")

	serverMetrics := bgrpc.NewServerMetrics(scope)

	crlSrv, crlListener, err := bgrpc.NewServer(c.Generator.GRPCCRLGenerator, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CA gRPC server")

	crlpb.RegisterCRLGeneratorServer(crlSrv, ci)

	crlHealth := health.NewServer()
	healthpb.RegisterHealthServer(crlSrv, crlHealth)

	go cmd.CatchSignals(logger, func() {
		crlHealth.Shutdown()
		crlSrv.GracefulStop()
	})

	cmd.FailOnError(cmd.FilterShutdownErrors(crlSrv.Serve(crlListener)),
		"CRLGenerator gRPC service failed")
}
