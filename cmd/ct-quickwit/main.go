package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"

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

func Index(url, pemPK string, start, end int64, continuous bool, entriesChan chan index.Document) error {
	derPK, err := base64.StdEncoding.DecodeString(pemPK)
	if err != nil {
		return err
	}

	ctclient, err := client.New(url, http.DefaultClient, jsonclient.Options{
		PublicKeyDER: derPK,
		UserAgent:    "ct-quickwit-indexer/0.2",
	})
	if err != nil {
		return err
	}

	scr := scanner.NewScanner(ctclient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     256,
			ParallelFetch: 1,
			StartIndex:    start,
			EndIndex:      end,
			Continuous:    continuous,
		},
		Matcher:     scanner.MatchAll{},
		PrecertOnly: false,
		NumWorkers:  1,
		BufferSize:  0,
	})

	err = scr.Scan(context.Background(), func(cert *ct.RawLogEntry) {
		entry, err := index.PrepareDocument(url, cert.Index, cert.Cert.Data, cert.Leaf.TimestampedEntry.Timestamp, false)
		if err != nil {
			log.Printf("Failed to prepare document: %v", err)
		}
		entriesChan <- entry
	}, func(precert *ct.RawLogEntry) {
		entry, err := index.PrepareDocument(url, precert.Index, precert.Cert.Data, precert.Leaf.TimestampedEntry.Timestamp, true)
		if err != nil {
			log.Printf("Failed to prepare document: %v", err)
		}
		entriesChan <- entry
	})
	if err != nil {
		return err
	}

	close(entriesChan)

	return nil
}
func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: ct-quickwit <config.json>")
	}

	/*
		f, err := os.Create("ct-quickwit.prof")
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	*/

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

	if err := Index(config.CTURL, config.CTPublicKey, config.CTStart, config.CTEnd, config.CTContinuous, entriesChan); err != nil {
		log.Fatal(err)
	}

	<-doneChan
}
