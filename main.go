package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Lukas-Les/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const port = "8080"
const maxChirpLen = 140

var badWords = [3]string{"kerfuffle", "sharbert", "fornax"}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerStats(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	page := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(page))
}

func (cfg *apiConfig) handlerResetStats(w http.ResponseWriter, req *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, 403, "Forbidden")
	}
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileserverHits.Swap(0)
	cfg.db.DeleteAllUsers(context.Background())
}

type RequestChirps struct {
	Body   string    `json:"body"`
	UserId uuid.UUID `json:"user_id"`
}

type Chirp struct {
	Id        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserId    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) handlerChirpsCreate(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	r := RequestChirps{}
	err := decoder.Decode(&r)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}
	if len(r.Body) > maxChirpLen {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	cleaned := cleanMessage(r.Body)
	params := database.CreateChirpParams{
		Body:   cleaned,
		UserID: r.UserId,
	}
	dbChripy, err := cfg.db.CreateChirp(context.Background(), params)
	if err != nil {
		respondWithError(w, 500, "failed to insert chirpy")
		return
	}
	chirpy := Chirp{
		Id:        dbChripy.ID,
		CreatedAt: dbChripy.CreatedAt,
		UpdatedAt: dbChripy.UpdatedAt,
		Body:      dbChripy.Body,
		UserId:    dbChripy.UserID,
	}
	respondWithJson(w, 201, chirpy)
}

func (cfg *apiConfig) handerGetAllChirps(w http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.db.GetAllChirps(context.Background())
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("failed to get chirps: %s", err))
	}
	result := []Chirp{}
	for _, dbChirp := range chirps {
		chirp := Chirp{
			Id:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserId:    dbChirp.UserID,
		}
		result = append(result, chirp)
	}
	respondWithJson(w, 200, result)
}

func (cfg *apiConfig) handlerGetChirp(w http.ResponseWriter, req *http.Request) {
	idStr := req.PathValue("id")
	chirpId, err := uuid.Parse(idStr)
	if err != nil {
		respondWithError(w, 400, "bad id")
		return
	}

	dbChirp, err := cfg.db.GetChirpById(req.Context(), chirpId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, 404, "not found")
			return
		}
		respondWithError(w, 500, err.Error())
		return
	}

	chirp := Chirp{
		Id:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
	}
	respondWithJson(w, 200, chirp)
}

type RequestUsers struct {
	Email string `json:"email"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) handlerUsersCreate(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	r := RequestUsers{}
	err := decoder.Decode(&r)
	if err != nil {
		respondWithError(w, 500, "failed to parse request")
		return
	}
	dbUser, err := cfg.db.CreateUser(context.Background(), r.Email)
	user := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("failed to create an user: %s", err))
	}
	respondWithJson(w, 201, user)
}

func main() {
	godotenv.Load()

	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalln("failed to connect to the db")
	}
	dbQueries := database.New(db)
	filepathRoot := http.Dir(".")
	mux := http.NewServeMux()
	cfg := apiConfig{fileserverHits: atomic.Int32{}, db: dbQueries, platform: os.Getenv("PLATFORM")}

	mux.Handle("/app/", http.StripPrefix("/app/", cfg.middlewareMetricsInc(http.FileServer(filepathRoot))))
	mux.HandleFunc("GET /api/healthz", handlerHeathz)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerStats)
	mux.HandleFunc("POST /admin/reset", cfg.handlerResetStats)
	mux.HandleFunc("POST /api/validate_chirp", handlerValidateChirp)
	mux.HandleFunc("POST /api/users", cfg.handlerUsersCreate)
	mux.HandleFunc("POST /api/chirps", cfg.handlerChirpsCreate)
	mux.HandleFunc("GET /api/chirps", cfg.handerGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{id}", cfg.handlerGetChirp)

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

type Request struct {
	Body string `json:"body"`
}

type ValidateResponse struct {
	Valid       bool   `json:"valid"`
	CleanedBody string `json:"cleaned_body"`
}

func handlerValidateChirp(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	decoder := json.NewDecoder(req.Body)
	r := Request{}
	err := decoder.Decode(&r)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}
	if len(r.Body) > maxChirpLen {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	cleaned := cleanMessage(r.Body)
	respondWithJson(w, 200, ValidateResponse{Valid: true, CleanedBody: cleaned})
}

func cleanMessage(msg string) string {
	lower := strings.Split(msg, " ")
	result := []string{}
	for _, word := range lower {
		isBad := false
		for _, badWord := range badWords {
			if strings.ToLower(word) == badWord {
				isBad = true
			}
		}
		if isBad {
			result = append(result, "****")
		} else {
			result = append(result, word)
		}
	}
	return strings.Join(result, " ")
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	errResponse := ErrorResponse{Error: msg}
	errResponseJson, err := json.Marshal(errResponse)
	if err != nil {
		log.Fatalf("%s", err)
	}
	w.WriteHeader(code)
	w.Write(errResponseJson)
}

func respondWithJson(w http.ResponseWriter, code int, payload any) {
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	}
	w.WriteHeader(code)
	w.Write(payloadJson)
}
