package middleware

import (
	"net/http"
	"net/url"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/sirupsen/logrus"

	"github.com/hellofresh/logging-go/context"
)

// New creates a new stats middleware
func New() func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.New(r.Context()))

			logger := context.WithContext(r.Context())
			logger.WithFields(logrus.Fields{"method": r.Method, "path": r.URL.Path}).Debug("Started request")

			// reverse proxy replaces original request with target request, so keep original one
			originalURL := &url.URL{}
			*originalURL = *r.URL

			fields := logrus.Fields{
				"method":      r.Method,
				"host":        r.Host,
				"request":     r.RequestURI,
				"remote-addr": r.RemoteAddr,
				"referer":     r.Referer(),
				"user-agent":  r.UserAgent(),
			}

			m := httpsnoop.CaptureMetrics(handler, w, r)

			fields["code"] = m.Code
			fields["duration"] = int(m.Duration / time.Millisecond)
			fields["duration-fmt"] = m.Duration.String()

			if originalURL.String() != r.URL.String() {
				fields["upstream-host"] = r.URL.Host
				fields["upstream-request"] = r.URL.RequestURI()
			}

			logger.WithFields(fields).Info("Completed handling request")
		})
	}
}
