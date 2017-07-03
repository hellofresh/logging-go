// +build !windows

package logging

import (
	"log/syslog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getSyslogPriority(t *testing.T) {
	_, err := getSyslogPriority(map[string]string{})
	assert.Error(t, err)

	_, err = getSyslogPriority(map[string]string{"severity": "severity"})
	assert.Error(t, err)

	_, err = getSyslogPriority(map[string]string{"facility": "facility"})
	assert.Error(t, err)

	_, err = getSyslogPriority(map[string]string{"severity": "severity", "facility": "facility"})
	assert.Error(t, err)

	_, err = getSyslogPriority(map[string]string{"severity": "LOG_INFO", "facility": "facility"})
	assert.Error(t, err)

	_, err = getSyslogPriority(map[string]string{"severity": "severity", "facility": "LOG_LOCAL0"})
	assert.Error(t, err)

	priority, err := getSyslogPriority(map[string]string{"severity": "LOG_INFO", "facility": "LOG_LOCAL0"})
	assert.NoError(t, err)
	assert.Equal(t, syslog.LOG_INFO|syslog.LOG_LOCAL0, priority)
}
