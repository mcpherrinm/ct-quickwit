package quickwit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mcpherrinm/ct-quickwit/index"
)

type Quickwit struct {
	url string
}

func New(baseURL, index string) *Quickwit {
	return &Quickwit{
		url: fmt.Sprintf("%s/api/v1/%s/ingest", baseURL, index),
	}
}

// WriteOut the documents to a file. Can be submitted with quickwit CLI
func WriteOut(filename string, entries chan index.Document, done chan bool) {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatal(err)
	}

	for entry := range entries {
		data := serialize([]index.Document{entry})
		_, err := file.Write(data.Bytes())
		if err != nil {
			log.Fatal(err)
		}
	}

	done <- true
}

func (qw *Quickwit) Run(batchSize int, entries chan index.Document, done chan bool) {
	// We store up to a full batch in the channel, plus the batch here
	docs := make([]index.Document, 0, batchSize)
	i := 0
	for entry := range entries {
		docs = append(docs, entry)
		if len(docs) >= batchSize {
			err := qw.Submit(docs)
			if err != nil {
				log.Fatal(err)
			}

			docs = docs[:0]

			i++
			log.Printf("Submitted batch %d", i)
		}
	}

	err := qw.Submit(docs)
	if err != nil {
		log.Fatal(err)
	}

	done <- true
}

// Submit documents
func (qw *Quickwit) Submit(documents []index.Document) error {
	buf := serialize(documents)

	return post429Retry(qw.url, buf)
}

func serialize(documents []index.Document) *bytes.Buffer {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	for _, document := range documents {
		err := enc.Encode(document)
		if err != nil {
			log.Printf("Error writing document: %v", err)
		}
	}
	return buf
}

func post429Retry(url string, buf *bytes.Buffer) error {
	for range 10 {
		resp, err := http.Post(url, "application/json", buf)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			time.Sleep(time.Second)
		} else {
			log.Printf("submitted: %v %v", resp.StatusCode, err)
			return nil
		}
	}
	return fmt.Errorf("too many 429s")
}
