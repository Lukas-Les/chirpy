package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

const port = "8080"

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerStats(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	val := fmt.Sprintf("Hits: %d", cfg.fileserverHits.Load())
	w.Write([]byte(val))
}

func (cfg *apiConfig) handlerResetStats(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileserverHits.Swap(0)
}

func main() {
	filepathRoot := http.Dir(".")
	mux := http.NewServeMux()
	cfg := apiConfig{fileserverHits: atomic.Int32{}}

	mux.Handle("/app/", http.StripPrefix("/app/", cfg.middlewareMetricsInc(http.FileServer(filepathRoot))))
	mux.HandleFunc("GET /healthz", handlerHeathz)
	mux.HandleFunc("GET /metrics", cfg.handlerStats)
	mux.HandleFunc("POST /reset", cfg.handlerResetStats)
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

func handlerHeathz(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}
