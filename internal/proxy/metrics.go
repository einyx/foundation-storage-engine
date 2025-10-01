package proxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

// Auth0Metrics holds metrics for Auth0 authentication
type Auth0Metrics struct {
	loginAttempts   prometheus.Counter
	loginSuccesses  prometheus.Counter
	loginFailures   prometheus.Counter
	jwtValidations  prometheus.Counter
	jwtCacheHits    prometheus.Counter
	jwtCacheMisses  prometheus.Counter
	sessionDuration prometheus.Histogram
	auth0APILatency prometheus.Histogram
}

var (
	metricsOnce sync.Once
	globalMetrics *Auth0Metrics
)

// NewAuth0Metrics creates new Auth0 metrics (singleton to avoid duplicate registration)
func NewAuth0Metrics() *Auth0Metrics {
	metricsOnce.Do(func() {
		globalMetrics = &Auth0Metrics{
			loginAttempts: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "foundation_storage_engine_auth0_login_attempts_total",
				Help: "Total number of Auth0 login attempts",
			}),
			loginSuccesses: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "foundation_storage_engine_auth0_login_successes_total",
				Help: "Total number of successful Auth0 logins",
			}),
			loginFailures: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "foundation_storage_engine_auth0_login_failures_total",
				Help: "Total number of failed Auth0 logins",
			}),
			jwtValidations: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "foundation_storage_engine_auth0_jwt_validations_total",
				Help: "Total number of JWT token validations",
			}),
			jwtCacheHits: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "foundation_storage_engine_auth0_jwt_cache_hits_total",
				Help: "Total number of JWT cache hits",
			}),
			jwtCacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "foundation_storage_engine_auth0_jwt_cache_misses_total",
				Help: "Total number of JWT cache misses",
			}),
			sessionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
				Name:    "foundation_storage_engine_auth0_session_duration_seconds",
				Help:    "Duration of Auth0 user sessions",
				Buckets: prometheus.ExponentialBuckets(60, 2, 10), // 1min to ~17hours
			}),
			auth0APILatency: prometheus.NewHistogram(prometheus.HistogramOpts{
				Name:    "foundation_storage_engine_auth0_api_duration_seconds",
				Help:    "Latency of Auth0 API calls",
				Buckets: prometheus.DefBuckets,
			}),
		}
		
		// Register metrics only once
		prometheus.MustRegister(
			globalMetrics.loginAttempts,
			globalMetrics.loginSuccesses,
			globalMetrics.loginFailures,
			globalMetrics.jwtValidations,
			globalMetrics.jwtCacheHits,
			globalMetrics.jwtCacheMisses,
			globalMetrics.sessionDuration,
			globalMetrics.auth0APILatency,
		)
	})
	
	return globalMetrics
}

// RecordLoginAttempt records a login attempt
func (m *Auth0Metrics) RecordLoginAttempt() {
	m.loginAttempts.Inc()
}

// RecordLoginSuccess records a successful login
func (m *Auth0Metrics) RecordLoginSuccess() {
	m.loginSuccesses.Inc()
}

// RecordLoginFailure records a failed login
func (m *Auth0Metrics) RecordLoginFailure() {
	m.loginFailures.Inc()
}

// RecordJWTValidation records a JWT validation
func (m *Auth0Metrics) RecordJWTValidation() {
	m.jwtValidations.Inc()
}

// RecordJWTCacheHit records a JWT cache hit
func (m *Auth0Metrics) RecordJWTCacheHit() {
	m.jwtCacheHits.Inc()
}

// RecordJWTCacheMiss records a JWT cache miss
func (m *Auth0Metrics) RecordJWTCacheMiss() {
	m.jwtCacheMisses.Inc()
}

// RecordSessionDuration records the duration of a user session
func (m *Auth0Metrics) RecordSessionDuration(duration time.Duration) {
	m.sessionDuration.Observe(duration.Seconds())
}

// RecordAuth0APICall records the latency of an Auth0 API call
func (m *Auth0Metrics) RecordAuth0APICall(duration time.Duration) {
	m.auth0APILatency.Observe(duration.Seconds())
}

// SecurityAuditLogger provides structured security event logging
type SecurityAuditLogger struct {
	logger *logrus.Logger
}

// NewSecurityAuditLogger creates a new security audit logger
func NewSecurityAuditLogger() *SecurityAuditLogger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	})
	return &SecurityAuditLogger{logger: logger}
}

// LogAuthEvent logs authentication-related security events
func (s *SecurityAuditLogger) LogAuthEvent(event string, userID string, details map[string]interface{}) {
	entry := s.logger.WithFields(logrus.Fields{
		"event_type": "auth",
		"event":      event,
		"user_id":    userID,
	})

	for key, value := range details {
		entry = entry.WithField(key, value)
	}

	entry.Info("Authentication event")
}

// LogAccessDenied logs access denied events
func (s *SecurityAuditLogger) LogAccessDenied(userID string, resource string, action string, reason string) {
	s.logger.WithFields(logrus.Fields{
		"event_type": "access_denied",
		"user_id":    userID,
		"resource":   resource,
		"action":     action,
		"reason":     reason,
	}).Warn("Access denied")
}

// LogSecurityEvent logs general security events
func (s *SecurityAuditLogger) LogSecurityEvent(event string, details map[string]interface{}) {
	entry := s.logger.WithFields(logrus.Fields{
		"event_type": "security",
		"event":      event,
	})

	for key, value := range details {
		entry = entry.WithField(key, value)
	}

	entry.Warn("Security event")
}