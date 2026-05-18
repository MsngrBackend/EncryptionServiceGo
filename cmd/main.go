package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"encryptionservice/internal/encryption"
)

func main() {
	ctx := context.Background()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:ultramegasecret@localhost:5432/messaging_db"
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	repo := encryption.NewRepository(pool)
	if err := repo.EnsureSchema(ctx); err != nil {
		log.Fatalf("failed to ensure encryption schema: %v", err)
	}

	svc := encryption.NewService(repo)
	mux := http.NewServeMux()
	encryption.NewHandler(svc).RegisterRoutes(mux)

	addr := os.Getenv("ENCRYPTION_SERVICE_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	log.Printf("encryption service listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
