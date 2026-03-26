package cloudwatch_test

import (
	"github.com/redhatinsights/platform-go-middlewares/v2/logging/cloudwatch"
	"go.uber.org/zap/zapcore"
)

// Compile-time assertion: *ZapWriteSyncer must satisfy zapcore.WriteSyncer.
var _ zapcore.WriteSyncer = (*cloudwatch.ZapWriteSyncer)(nil)
