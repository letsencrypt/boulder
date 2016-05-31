package main

import (
	"os"

	ct "github.com/google/certificate-transparency/go"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/publisher"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/rpc"
)

const clientName = "Publisher"

func main() {
	app := cmd.NewAppShell("boulder-publisher", "Submits issued certificates to CT logs")
	app.Action = func(c cmd.Config, stats metrics.Statter, logger blog.Logger) {
		logs := make([]*publisher.Log, len(c.Common.CT.Logs))
		var err error
		for i, ld := range c.Common.CT.Logs {
			logs[i], err = publisher.NewLog(ld.URI, ld.Key)
			cmd.FailOnError(err, "Unable to parse CT log description")
		}

		if c.Common.CT.IntermediateBundleFilename == "" {
			logger.Err("No CT submission bundle provided")
			os.Exit(1)
		}
		pemBundle, err := core.LoadCertBundle(c.Common.CT.IntermediateBundleFilename)
		cmd.FailOnError(err, "Failed to load CT submission bundle")
		bundle := []ct.ASN1Cert{}
		for _, cert := range pemBundle {
			bundle = append(bundle, ct.ASN1Cert(cert.Raw))
		}

		pubi := publisher.New(bundle, logs, c.Publisher.SubmissionTimeout.Duration, logger)

		go cmd.DebugServer(c.Publisher.DebugAddr)
		go cmd.ProfileCmd("Publisher", stats)

		amqpConf := c.Publisher.AMQP
		pubi.SA, err = rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create SA client")

		if c.Publisher.GRPC != nil {
			s, l, err := bgrpc.NewServer(c.Publisher.GRPC)
			cmd.FailOnError(err, "Failed to setup gRPC server")
			gw := bgrpc.NewPublisherServerWrapper(pubi)
			pubPB.RegisterPublisherServer(s, gw)
			err = s.Serve(l)
			cmd.FailOnError(err, "gRPC service failed")
		} else {
			pubs, err := rpc.NewAmqpRPCServer(amqpConf, c.Publisher.MaxConcurrentRPCServerRequests, stats)
			cmd.FailOnError(err, "Unable to create Publisher RPC server")
			err = rpc.NewPublisherServer(pubs, pubi)
			cmd.FailOnError(err, "Unable to setup Publisher RPC server")

			err = pubs.Start(amqpConf)
			cmd.FailOnError(err, "Unable to run Publisher RPC server")
		}
	}

	app.Run()
}
