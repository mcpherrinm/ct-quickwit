package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/mcpherrinm/ct-quickwit/index"
	"github.com/mcpherrinm/ct-quickwit/quickwit"
)

// Config holds the JSON configuration for this tool
type Config struct {
	CTPublicKey   string
	CTURL         string
	CTStart       int64
	CTEnd         int64
	CTContinuous  bool
	QuickwitURL   string
	QuickwitIndex string
	BatchSize     int
	WriteFilename string
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: ct-quickwit <config.json>")
	}

	configFile, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Opening config file %s: %v", os.Args[1], err)
	}

	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Unmarshaling config file %s: %v", os.Args[1], err)
	}

	entriesChan := make(chan index.Document, 1024)

	doneChan := make(chan bool)

	if config.WriteFilename != "" {
		// If we have a filename, just dump to it instead of QW
		go quickwit.WriteOut(config.WriteFilename, entriesChan, doneChan)
	} else {
		qw := quickwit.New(config.QuickwitURL, config.QuickwitIndex)
		go qw.Run(config.BatchSize, entriesChan, doneChan)
	}

	if err := index.Index(config.CTURL, config.CTPublicKey, config.CTStart, config.CTEnd, config.CTContinuous, entriesChan); err != nil {
		log.Fatal(err)
	}

	<-doneChan
}
