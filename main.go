package main

import (
	"flag"
	"os"

	"github.com/ror-shubham/multi_issuer_payment/multi_issuer_payment"
	"github.com/tendermint/abci/server"
	"github.com/tendermint/abci/types"
	cmn "github.com/tendermint/tmlibs/common"
	"github.com/tendermint/tmlibs/log"
)

func main() {

	addrPtr := flag.String("addr", "tcp://0.0.0.0:46658", "Listen address")
	abciPtr := flag.String("abci", "socket", "socket | grpc")
	//persistencePtr := flag.String("persist", "", "directory to use for a database")
	flag.Parse()

	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))

	// Create the application - in memory or persisted to disk
	var app types.Application
	app = multi_issuer_payment.NewMultiIssuerPaymentApplication()
	

	// Start the listener
	srv, err := server.NewServer(*addrPtr, *abciPtr, app)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	srv.SetLogger(logger.With("module", "abci-server"))
	if _, err := srv.Start(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	// Wait forever
	cmn.TrapSignal(func() {
		// Cleanup
		srv.Stop()
	})

}
