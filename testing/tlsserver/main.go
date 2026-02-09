package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain")
	slog.InfoContext(r.Context(), "HTTPS", "method", r.Method, "path", r.URL.Path)
	_, err := fmt.Fprintf(w, "Hello TLS\n")
	if err != nil {
		slog.ErrorContext(r.Context(), "can't write response", "error", err)
	}
}

func main() {
	// Create a new HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", helloHandler)

	server := &http.Server{
		Addr:    ":8443",
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Println("Starting HTTPS server on https://localhost:8443")

	// Start the server with TLS
	// You'll need cert.pem and key.pem files
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
