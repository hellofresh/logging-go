package context

import (
	"context"

	"github.com/sirupsen/logrus"
)

type loggerKeyType int

const loggerKey loggerKeyType = iota

// New returns a context that has a logrus logger
func New(ctx context.Context) context.Context {
	return context.WithValue(ctx, loggerKey, WithContext(ctx))
}

// WithContext returns a logrus logger from the context
func WithContext(ctx context.Context) *logrus.Logger {
	if ctx == nil {
		return logrus.StandardLogger()
	}

	if ctxLogger, ok := ctx.Value(loggerKey).(*logrus.Logger); ok {
		return ctxLogger
	}

	return logrus.StandardLogger()
}
