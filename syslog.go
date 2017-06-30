// +build !windows

package logging

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/syslog"
)

func (c LogConfig) initSyslogHook(h LogHook) error {
	if err := c.validateRequiredHookSettings(h, []string{"network"}); err != nil {
		return err
	}
	network, _ := h.Settings["network"]

	priority, err := getSyslogPriority(h.Settings)
	if nil != err {
		log.WithError(err).WithField("hook", h.Format).Error("Failed to configure hook")
		return ErrFailedToConfigureLogHook
	}

	tag, _ := h.Settings["tag"]
	hook, err := logrus_syslog.NewSyslogHook(network, fmt.Sprintf("%s:%s", h.Settings["host"], h.Settings["port"]), priority, tag)
	if nil != err {
		log.WithError(err).WithField("hook", h.Format).Error("Failed to configure hook")
		return ErrFailedToConfigureLogHook
	}

	log.AddHook(hook)

	return nil
}
