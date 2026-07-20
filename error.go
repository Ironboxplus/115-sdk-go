package sdk

import (
	"errors"
	"fmt"
)

var ErrObjectNotFound = errors.New("object not found")

var ErrDataEmpty = errors.New("api returned empty data")

const (
	// CodeRefreshFrequently means the refresh chain was rejected. Treat the
	// complete pair as dead and recover from a peer instead of retrying.
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
