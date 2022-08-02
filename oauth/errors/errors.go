package errors

type ResponseError struct {
	Code    int    `json:"code"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

func FormatError(code int, error string, message string) *ResponseError {
	return &ResponseError{
		Code:    code,
		Error:   error,
		Message: message,
	}
}
