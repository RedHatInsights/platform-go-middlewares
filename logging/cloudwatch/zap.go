package cloudwatch

// ZapWriteSyncer wraps a BatchWriter to satisfy zapcore.WriteSyncer,
// allowing it to be passed directly to zapcore.NewCore.
type ZapWriteSyncer struct {
	w *BatchWriter
}

func NewZapWriteSyncer(w *BatchWriter) *ZapWriteSyncer {
	return &ZapWriteSyncer{w: w}
}

func (z *ZapWriteSyncer) Write(p []byte) (int, error) {
	return z.w.Write(p)
}

// Sync flushes any buffered log events to CloudWatch.
func (z *ZapWriteSyncer) Sync() error {
	return z.w.Flush()
}
