package sdk

import (
	"errors"
	"fmt"
)

var ErrObjectNotFound = errors.New("object not found")

var ErrDataEmpty = errors.New("api returned empty data")

const (
	// CodeRefreshFrequently means the refresh endpoint is temporarily throttled.
	// Keep the pair and retry after a cooldown; this is not proof that the
	// refresh_token was consumed or revoked.
	CodeRefreshFrequently int64 = 40140117
	// CodeRefreshTokenError means the stored refresh_token is dead (consumed or revoked).
	// No amount of retrying can recover it; re-authorization is required.
	CodeRefreshTokenError int64 = 40140120
)

type Error struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("code: %d, message: %s", e.Code, e.Message)
}

func (e *Error) Is(target error) bool {
	return e != nil && target == ErrObjectNotFound && e.Code == 430004
}
