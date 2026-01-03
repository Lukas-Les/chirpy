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

	"github.com/Lukas-Les/chirpy/internal/auth"
	"github.com/Lukas-Les/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const port = "8080"
const maxChirpLen = 140
const defaultErrorMsg = "Something bad happened"

var badWords = [3]string{"kerfuffle", "sharbert", "fornax"}

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
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
		respondWithError(w, 500, "Error decoding response")
		return
	}
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, 500, "Error getting token")
		return
	}
	userId, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, 401, err.Error())
		return
	}
	if len(r.Body) > maxChirpLen {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	cleaned := cleanMessage(r.Body)
	params := database.CreateChirpParams{
		Body:   cleaned,
		UserID: userId,
	}
	dbChripy, err := cfg.db.CreateChirp(context.Background(), params)
	if err != nil {
		respondWithError(w, 500, err.Error())
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
	var chirps []database.Chirp
	var err error
	authorIdStr := req.URL.Query().Get("author_id")
	if authorIdStr != "" {
		authorId, err := uuid.Parse(authorIdStr)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		chirps, err = cfg.db.GetChirpsByUser(req.Context(), authorId)
	} else {
		chirps, err = cfg.db.GetAllChirps(req.Context())
	}
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
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

func (cfg *apiConfig) handlerUsersCreate(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	r := RequestUsers{}
	err := decoder.Decode(&r)
	if err != nil {
		respondWithError(w, 500, "failed to parse request")
		return
	}
	fmt.Printf("creating with:\n\tusername: %s\npassord: %s\n", r.Email, r.Password)
	hashedPassword, err := auth.HashPassword(r.Password)
	fmt.Printf("hashed_password: %s\n", hashedPassword)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "internal error")
		return
	}
	params := database.CreateUserParams{Email: r.Email, HashedPassword: hashedPassword}
	dbUser, err := cfg.db.CreateUser(req.Context(), params)
	user := User{
		ID:          dbUser.ID,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
	}
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("failed to create an user: %s", err))
		return
	}
	respondWithJson(w, 201, user)
}

type RequestLogIn struct {
	Password         string `json:"password"`
	Email            string `json:"email"`
	ExpiresInSeconds string `json:"expires_in_seconds"`
}

type ResponseLogIn struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

func (cfg *apiConfig) handlerLogIn(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	r := RequestLogIn{}
	err := decoder.Decode(&r)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	dbUser, err := cfg.db.GetUserByEmail(req.Context(), r.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	fmt.Printf("logging in with:\n\tusername: %s\npassord: %s\n", r.Email, r.Password)
	fmt.Printf("hashed_password: %s\n", dbUser.HashedPassword)

	fmt.Printf("password len=%d, bytes=%v\n", len(r.Password), []byte(r.Password))
	fmt.Printf("hash len=%d, bytes=%v\n", len(dbUser.HashedPassword), []byte(dbUser.HashedPassword))
	isValid, err := auth.CheckPasswordHash(r.Password, dbUser.HashedPassword)
	fmt.Printf("isValid=%v, err=%v\n", isValid, err)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	if !isValid {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}
	var expiresIn time.Duration
	if r.ExpiresInSeconds != "" {
		expiresIn, err = time.ParseDuration(fmt.Sprintf("%ss", r.ExpiresInSeconds))
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Something bad happened")
			return
		}
	} else {
		expiresIn = time.Hour
	}

	token, err := auth.MakeJWT(dbUser.ID, cfg.jwtSecret, expiresIn)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, defaultErrorMsg)
	}
	refToken, err := auth.MakeRefreshToken()
	refTokenParams := database.CreateRefreshTokenParams{
		Token:     refToken,
		UserID:    dbUser.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
	}
	_, err = cfg.db.CreateRefreshToken(req.Context(), refTokenParams)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := ResponseLogIn{
		ID:           dbUser.ID,
		CreatedAt:    dbUser.CreatedAt,
		UpdatedAt:    dbUser.UpdatedAt,
		Email:        dbUser.Email,
		Token:        token,
		RefreshToken: refToken,
		IsChirpyRed:  dbUser.IsChirpyRed,
	}
	respondWithJson(w, http.StatusOK, resp)
}

type RefreshResponse struct {
	Token string `json:"token"`
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dbRefReshToken, err := cfg.db.GetRefreshToken(req.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	jwtToken, err := auth.MakeJWT(dbRefReshToken.UserID, cfg.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusOK, RefreshResponse{Token: jwtToken})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	err = cfg.db.Revoke(req.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type UpdateUserRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type UpdateUserResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	userId, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	decoder := json.NewDecoder(req.Body)
	r := UpdateUserRequest{}
	err = decoder.Decode(&r)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hashedPassword, err := auth.HashPassword(r.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
	}
	updateParams := database.UpdateUserParams{
		Email:          r.Email,
		HashedPassword: hashedPassword,
		ID:             userId,
	}
	dbUpdated, err := cfg.db.UpdateUser(req.Context(), updateParams)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated := UpdateUserResponse{
		ID:        dbUpdated.ID,
		CreatedAt: dbUpdated.CreatedAt,
		UpdatedAt: dbUpdated.UpdatedAt,
		Email:     r.Email,
	}
	respondWithJson(w, http.StatusOK, updated)
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
	}
	userId, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	chirpIdStr := req.PathValue("id")
	chirpId, err := uuid.Parse(chirpIdStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	chirp, err := cfg.db.GetChirpById(req.Context(), chirpId)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	if chirp.UserID != userId {
		respondWithError(w, http.StatusForbidden, "")
		return
	}
	err = cfg.db.DeleteChirp(req.Context(), chirpId)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type PolkaWebHookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

func (cfg *apiConfig) handlerPolkaWebHook(w http.ResponseWriter, req *http.Request) {
	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "wrong api key")
		return
	}
	decoder := json.NewDecoder(req.Body)
	r := PolkaWebHookRequest{}
	err = decoder.Decode(&r)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if r.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	userId, err := uuid.Parse(r.Data.UserID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	params := database.UpdateUserChirpyRedParams{
		IsChirpyRed: true,
		ID:          userId,
	}
	err = cfg.db.UpdateUserChirpyRed(context.Background(), params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	cfg := apiConfig{fileserverHits: atomic.Int32{}, db: dbQueries, platform: os.Getenv("PLATFORM"), jwtSecret: os.Getenv("JWT_SECRET"), polkaKey: os.Getenv("POLKA_KEY")}

	mux.Handle("/app/", http.StripPrefix("/app/", cfg.middlewareMetricsInc(http.FileServer(filepathRoot))))
	mux.HandleFunc("GET /api/healthz", handlerHeathz)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerStats)
	mux.HandleFunc("POST /admin/reset", cfg.handlerResetStats)

	mux.HandleFunc("POST /api/validate_chirp", handlerValidateChirp)
	mux.HandleFunc("POST /api/users", cfg.handlerUsersCreate)
	mux.HandleFunc("POST /api/chirps", cfg.handlerChirpsCreate)
	mux.HandleFunc("GET /api/chirps", cfg.handerGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{id}", cfg.handlerGetChirp)
	mux.HandleFunc("POST /api/login", cfg.handlerLogIn)
	mux.HandleFunc("POST /api/refresh", cfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", cfg.handlerRevoke)
	mux.HandleFunc("PUT /api/users", cfg.handlerUpdateUser)
	mux.HandleFunc("DELETE /api/chirps/{id}", cfg.handlerDeleteChirp)

	mux.HandleFunc("POST /api/polka/webhooks", cfg.handlerPolkaWebHook)

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
