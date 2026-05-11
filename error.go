package sdk

import (
	"errors"
	"fmt"
)

var ErrDataEmpty = errors.New("api returned empty data")

type Error struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("code: %d, message: %s", e.Code, e.Message)
}
