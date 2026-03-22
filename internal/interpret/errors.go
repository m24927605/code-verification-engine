package interpret

import "errors"

var (
	// ErrTimeout is returned when a provider request exceeds its deadline.
	ErrTimeout = errors.New("interpret: request timed out")

	// ErrBudgetExceeded is returned when the call budget has been exhausted.
	ErrBudgetExceeded = errors.New("interpret: call budget exceeded")

	// ErrRetryExhausted is returned when all retry attempts have failed.
	ErrRetryExhausted = errors.New("interpret: all retry attempts failed")

	// ErrResponseTooLarge is returned when the response body exceeds MaxResponseBytes.
	ErrResponseTooLarge = errors.New("interpret: response too large")
)
