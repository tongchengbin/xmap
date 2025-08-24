package scanner

import (
	"errors"
)

var (
	ConnectionError  = errors.New("connection error")
	ReadTimeoutError = errors.New("read data error")
	WriteDataError   = errors.New("write data error")
)
