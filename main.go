package main

import (
	"log"
	"net/http"
)

const port = "8080"

func main() {
	filepathRoot := http.Dir(".")
	mux := http.NewServeMux()

	mux.Handle("/", http.FileServer(filepathRoot))
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}
