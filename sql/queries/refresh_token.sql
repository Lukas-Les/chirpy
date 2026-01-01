-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES (
    $1,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    $2,
    $3
)
RETURNING *;

-- name: GetRefreshToken :one
SELECT * FROM  refresh_tokens
WHERE  token = $1 AND revoked_at IS NULL AND CURRENT_TIMESTAMP < expires_at;

-- name: Revoke :exec
UPDATE refresh_tokens
SET revoked_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
    WHERE token = $1;
