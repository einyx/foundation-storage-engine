package logging

import (
	"fmt"

	"github.com/getsentry/sentry-go"
	"github.com/sirupsen/logrus"
)

// SentryHook is a logrus hook that sends errors to Sentry
type SentryHook struct {
	levels []logrus.Level
}

// NewSentryHook creates a new Sentry hook for logrus
func NewSentryHook(levels []logrus.Level) *SentryHook {
	if levels == nil {
		levels = []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
			logrus.WarnLevel,
		}
	}
	return &SentryHook{
		levels: levels,
	}
}

// Fire is called when a log event is fired.
func (hook *SentryHook) Fire(entry *logrus.Entry) error {
	// Don't send to Sentry if it's not initialized
	if sentry.CurrentHub() == nil {
		return nil
	}

	// Create a new event
	event := sentry.NewEvent()
	event.Timestamp = entry.Time
	event.Message = entry.Message
	event.Level = logrusLevelToSentryLevel(entry.Level)
	event.Logger = "logrus"

	// Add fields as extra data
	event.Extra = make(map[string]interface{})
	for k, v := range entry.Data {
		event.Extra[k] = v
	}

	// Check if there's an error field
	if err, ok := entry.Data["error"].(error); ok {
		event.Exception = []sentry.Exception{{
			Type:  fmt.Sprintf("%T", err),
			Value: err.Error(),
		}}
	}

	// Add tags
	event.Tags = make(map[string]string)
	if method, ok := entry.Data["method"].(string); ok {
		event.Tags["http.method"] = method
	}
	if path, ok := entry.Data["path"].(string); ok {
		event.Tags["http.path"] = path
	}
	if status, ok := entry.Data["status"].(int); ok {
		event.Tags["http.status_code"] = fmt.Sprintf("%d", status)
	}
	if operation, ok := entry.Data["operation"].(string); ok {
		event.Tags["operation"] = operation
	}
	if bucket, ok := entry.Data["bucket"].(string); ok {
		event.Tags["s3.bucket"] = bucket
	}
	if key, ok := entry.Data["key"].(string); ok {
		event.Tags["s3.key"] = key
	}

	// Send to Sentry
	hub := sentry.CurrentHub()
	hub.CaptureEvent(event)

	return nil
}

// Levels returns the logging levels for which the hook is fired.
func (hook *SentryHook) Levels() []logrus.Level {
	return hook.levels
}

// logrusLevelToSentryLevel converts logrus log levels to Sentry levels
func logrusLevelToSentryLevel(level logrus.Level) sentry.Level {
	switch level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return sentry.LevelFatal
	case logrus.ErrorLevel:
		return sentry.LevelError
	case logrus.WarnLevel:
		return sentry.LevelWarning
	case logrus.InfoLevel:
		return sentry.LevelInfo
	case logrus.DebugLevel, logrus.TraceLevel:
		return sentry.LevelDebug
	default:
		return sentry.LevelInfo
	}
}

// WithSentryBreadcrumb returns a logrus hook that creates Sentry breadcrumbs
type BreadcrumbHook struct {
	levels []logrus.Level
}

// NewBreadcrumbHook creates a new breadcrumb hook for logrus
func NewBreadcrumbHook(levels []logrus.Level) *BreadcrumbHook {
	if levels == nil {
		levels = []logrus.Level{
			logrus.InfoLevel,
			logrus.WarnLevel,
			logrus.ErrorLevel,
		}
	}
	return &BreadcrumbHook{
		levels: levels,
	}
}

// Fire is called when a log event is fired.
func (hook *BreadcrumbHook) Fire(entry *logrus.Entry) error {
	// Don't create breadcrumbs if Sentry is not initialized
	if sentry.CurrentHub() == nil {
		return nil
	}

	breadcrumb := &sentry.Breadcrumb{
		Type:      "log",
		Category:  "logrus",
		Message:   entry.Message,
		Level:     logrusLevelToSentryLevel(entry.Level),
		Data:      make(map[string]interface{}),
		Timestamp: entry.Time,
	}

	// Add selected fields to breadcrumb data
	for k, v := range entry.Data {
		switch k {
		case "method", "path", "status", "operation", "bucket", "key", "size":
			breadcrumb.Data[k] = v
		}
	}

	hub := sentry.CurrentHub()
	hub.Scope().AddBreadcrumb(breadcrumb, 0)

	return nil
}

// Levels returns the logging levels for which the hook is fired.
func (hook *BreadcrumbHook) Levels() []logrus.Level {
	return hook.levels
}