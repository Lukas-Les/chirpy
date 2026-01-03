-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    $1,
    $2
)
RETURNING *;

-- name: GetAllChirps :many
SELECT * FROM chirps
ORDER BY created_at;

-- name: GetChirpById :one
SELECT * FROM chirps
WHERE id = $1;

-- name: GetChirpByUserAndId :one
SELECT * FROM chirps
WHERE id = $1 and user_id = $2;

-- name: DeleteChirp :exec
DELETE FROM chirps
WHERE id = $1;
