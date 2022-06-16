package cloudwatch

import (
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

// LogrusHook implements the logrus.LogrusHook interface, writing lines to its
// writer.
type LogrusHook struct {
	w io.Writer
}

func NewLogrusHook(w io.Writer) *LogrusHook {
	return &LogrusHook{
		w: w,
	}
}

// Force flushing of currently stored messages
func (h *LogrusHook) Flush() error {
	batchWriter, ok := h.w.(*BatchWriter)
	if !ok {
		return fmt.Errorf("cannot cast to *BatchWriter")
	}
	return batchWriter.Flush()
}

// Function alias for compatibility with zap logging
func (h *LogrusHook) Sync() error {
	return h.Flush()
}

func (h *LogrusHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read entry, %v", err)
		return err
	}

	switch entry.Level {
	case logrus.PanicLevel:
		fallthrough
	case logrus.FatalLevel:
		fallthrough
	case logrus.ErrorLevel:
		fallthrough
	case logrus.WarnLevel:
		fallthrough
	case logrus.InfoLevel:
		fallthrough
	case logrus.DebugLevel:
		_, err := h.w.Write([]byte(line))
		return err
	default:
		return nil
	}
}

func (h *LogrusHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}
