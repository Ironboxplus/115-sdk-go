package sdk

import (
	"errors"
	"fmt"
)

var ErrObjectNotFound = errors.New("object not found")

var ErrDataEmpty = errors.New("api returned empty data")

const (
	// CodeRefreshFrequently is returned when 115 rejects the credential chain for
	// refresh frequency. The complete pair must be replaced from a peer or re-auth;
	// AuthRequest never retries it locally.
	CodeRefreshFrequently int64 = 40140117
	// CodeRefreshTokenError means 115 rejected the credential chain while refreshing.
	// No local retry can recover it; a peer replacement or re-authorization is required.
	CodeRefreshTokenError int64 = 40140120
)

type Error struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("code: %d, message: %s", e.Code, e.Message)
}
