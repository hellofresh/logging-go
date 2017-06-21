package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/syslog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bshuster-repo/logrus-logstash-hook"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/syslog"
	"github.com/spf13/viper"
	"gopkg.in/gemnasium/logrus-graylog-hook.v2"
)

var (
	// ErrUnknownLogHookFormat is the error returned when trying to initialise hook of unknown format
	ErrUnknownLogHookFormat = errors.New("Failed to init log hooks: unknown hook found")
	// ErrMissingLogHookSetting is the error returned when trying to initialise hook with required settings missing
	ErrMissingLogHookSetting = errors.New("Failed to init log hooks: missing required hook setting")
	// ErrFailedToConfigureLogHook is the error returned when hook configuring failed for some reasons
	ErrFailedToConfigureLogHook = errors.New("Failed to init log hooks: failed to configure hook")
)

var (
	severitiesMap = map[string]syslog.Priority{
		"LOG_EMERG":   syslog.LOG_EMERG,
		"LOG_ALERT":   syslog.LOG_ALERT,
		"LOG_CRIT":    syslog.LOG_CRIT,
		"LOG_ERR":     syslog.LOG_ERR,
		"LOG_WARNING": syslog.LOG_WARNING,
		"LOG_NOTICE":  syslog.LOG_NOTICE,
		"LOG_INFO":    syslog.LOG_INFO,
		"LOG_DEBUG":   syslog.LOG_DEBUG,
	}

	facilitiesMap = map[string]syslog.Priority{
		"LOG_KERN":     syslog.LOG_KERN,
		"LOG_USER":     syslog.LOG_USER,
		"LOG_MAIL":     syslog.LOG_MAIL,
		"LOG_DAEMON":   syslog.LOG_DAEMON,
		"LOG_AUTH":     syslog.LOG_AUTH,
		"LOG_SYSLOG":   syslog.LOG_SYSLOG,
		"LOG_LPR":      syslog.LOG_LPR,
		"LOG_NEWS":     syslog.LOG_NEWS,
		"LOG_UUCP":     syslog.LOG_UUCP,
		"LOG_CRON":     syslog.LOG_CRON,
		"LOG_AUTHPRIV": syslog.LOG_AUTHPRIV,
		"LOG_FTP":      syslog.LOG_FTP,
		"LOG_LOCAL0":   syslog.LOG_LOCAL0,
		"LOG_LOCAL1":   syslog.LOG_LOCAL1,
		"LOG_LOCAL2":   syslog.LOG_LOCAL2,
		"LOG_LOCAL3":   syslog.LOG_LOCAL3,
		"LOG_LOCAL4":   syslog.LOG_LOCAL4,
		"LOG_LOCAL5":   syslog.LOG_LOCAL5,
		"LOG_LOCAL6":   syslog.LOG_LOCAL6,
		"LOG_LOCAL7":   syslog.LOG_LOCAL7,
	}
)

// LogFormat type for enumerating available log formats
type LogFormat string

// LogWriter for enumerating available log writers
type LogWriter string

const (
	// Text is plain text log format
	Text LogFormat = "text"
	// JSON is json log format
	JSON LogFormat = "json"
	// Logstash is json log format with some additional fields required for logstash
	Logstash LogFormat = "logstash"

	// StdErr is os stderr log writer
	StdErr LogWriter = "stderr"
	// StdOut is os stdout log writer
	StdOut LogWriter = "stdout"
	// Discard is the quite mode for log writer aka /dev/null
	Discard LogWriter = "discard"

	// HookLogstash is logstash hook format
	HookLogstash = "logstash"
	// HookSyslog is syslog hook format
	HookSyslog = "syslog"
	// HookGraylog is graylog hook format
	HookGraylog = "graylog"

	defaultLevel  = "info"
	defaultFormat = "json"
	defaultWriter = "stderr"
)

// LogHook is a struct holding settings for each enabled hook
type LogHook struct {
	Format   string
	Settings map[string]string
}

// LogHooks is collection of enabled hooks
type LogHooks []LogHook

// UnmarshalText is an implementation of encoding.TextUnmarshaler for LogHooks type
func (lh *LogHooks) UnmarshalText(text []byte) error {
	var hooks []LogHook
	err := json.Unmarshal(text, &hooks)
	if nil != err {
		return err
	}

	*lh = hooks

	return nil
}

// LogConfig is the struct that stores all the logging configuration and routines for applying configurations
// to logger
type LogConfig struct {
	Level          string            `envconfig:"LOG_LEVEL"`
	Format         LogFormat         `envconfig:"LOG_FORMAT"`
	FormatSettings map[string]string `envconfig:"LOG_FORMAT_SETTINGS"`
	Writer         LogWriter         `envconfig:"LOG_WRITER"`
	Hooks          LogHooks          `envconfig:"LOG_HOOKS"`

	mustFlushHooks []log.Hook
}

// Apply configures logger and all enabled hooks
func (c LogConfig) Apply() error {
	level, err := log.ParseLevel(strings.ToLower(c.Level))
	if nil != err {
		return err
	}
	log.SetLevel(level)

	log.SetOutput(c.getWriter())
	log.SetFormatter(c.getFormatter())

	return c.initHooks()
}

// Flush waits for all buffering loggers to finish flushing buffers
func (c LogConfig) Flush() {
	for i := range c.mustFlushHooks {
		if h, ok := c.mustFlushHooks[i].(*graylog.GraylogHook); ok {
			h.Flush()
		}
	}
}

func (c LogConfig) getWriter() io.Writer {
	switch c.Writer {
	case StdOut:
		return os.Stdout
	case Discard:
		return ioutil.Discard
	case StdErr:
		fallthrough
	default:
		return os.Stderr
	}
}

func (c LogConfig) getFormatter() log.Formatter {
	switch c.Format {
	case JSON:
		return &log.JSONFormatter{}
	case Logstash:
		return getLogstashFormatter(c.FormatSettings)
	case Text:
		fallthrough
	default:
		return &log.TextFormatter{}
	}
}

func (c LogConfig) initHooks() error {
	for _, h := range c.Hooks {
		if err := c.validateRequiredHookSettings(h, []string{"host", "port"}); err != nil {
			return err
		}
		host, _ := h.Settings["host"]
		port, _ := h.Settings["port"]

		switch h.Format {
		case HookLogstash:
			if err := c.validateRequiredHookSettings(h, []string{"network"}); err != nil {
				return err
			}
			network, _ := h.Settings["network"]

			conn, err := net.Dial(network, fmt.Sprintf("%s:%s", host, port))
			if nil != err {
				log.WithError(err).WithField("hook", h.Format).Error("Failed to connect to logstash")
				return ErrFailedToConfigureLogHook
			}

			formatter := getLogstashFormatter(h.Settings)

			hook := logrustash.New(conn, formatter)
			log.AddHook(hook)

		case HookSyslog:
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
			hook, err := logrus_syslog.NewSyslogHook(network, fmt.Sprintf("%s:%s", host, port), priority, tag)
			if nil != err {
				log.WithError(err).WithField("hook", h.Format).Error("Failed to configure hook")
				return ErrFailedToConfigureLogHook
			}

			log.AddHook(hook)

		case HookGraylog:
			var async bool
			var err error
			if asyncStr, ok := h.Settings["async"]; ok {
				async, err = strconv.ParseBool(asyncStr)
				if nil != err {
					log.WithError(err).WithField("hook", h.Format).Error("Failed to parse async setting")
					return ErrFailedToConfigureLogHook
				}
			}

			extra := make(map[string]interface{})
			for k, v := range h.Settings {
				if k != "host" && k != "port" && k != "async" {
					extra[k] = v
				}
			}
			var hook *graylog.GraylogHook
			if async {
				hook = graylog.NewGraylogHook(fmt.Sprintf("%s:%s", host, port), extra)
			} else {
				hook = graylog.NewAsyncGraylogHook(fmt.Sprintf("%s:%s", host, port), extra)
				c.mustFlushHooks = append(c.mustFlushHooks, hook)
			}

			log.AddHook(hook)

		default:
			return ErrUnknownLogHookFormat
		}
	}

	return nil
}

func (c LogConfig) validateRequiredHookSettings(h LogHook, required []string) error {
	for i := range required {
		if _, ok := h.Settings[required[i]]; !ok {
			log.WithFields(log.Fields{"hook": h.Format, "setting": required[i]}).Error("Missing required hook setting")
			return ErrMissingLogHookSetting
		}
	}
	return nil
}

func getSyslogPriority(settings map[string]string) (syslog.Priority, error) {
	severity, ok := settings["severity"]
	if !ok {
		return 0, fmt.Errorf("Syslog severity setting is not set")
	}

	facility, ok := settings["facility"]
	if !ok {
		return 0, fmt.Errorf("Syslog facility setting is not set")
	}

	severityPriority, ok := severitiesMap[severity]
	if !ok {
		return 0, fmt.Errorf("Unknown syslog severity value")
	}

	facilityPriority, ok := facilitiesMap[facility]
	if !ok {
		return 0, fmt.Errorf("Unknown syslog facility value")
	}

	return severityPriority | facilityPriority, nil
}

func getLogstashFormatter(settings map[string]string) log.Formatter {
	logstashType, _ := settings["type"]
	logstashTSFormat, _ := settings["ts"]
	tsFormats := map[string]string{
		"RFC3339":     time.RFC3339,
		"RFC3339Nano": time.RFC3339Nano,
	}
	tsFormat, _ := tsFormats[logstashTSFormat]

	formatter := logrustash.DefaultFormatter(log.Fields{"type": logstashType})
	logstashFormatter, _ := formatter.(logrustash.LogstashFormatter)
	jsonFormatter, _ := logstashFormatter.Formatter.(*log.JSONFormatter)

	jsonFormatter.TimestampFormat = tsFormat

	return formatter
}

// InitDefaults initialises default logger settings
func InitDefaults(v *viper.Viper, prefix string) {
	if prefix != "" {
		if !strings.HasSuffix(prefix, ".") {
			prefix += "."
		}
	}

	v.SetDefault(prefix+"level", defaultLevel)
	v.SetDefault(prefix+"format", defaultFormat)
	v.SetDefault(prefix+"writer", defaultWriter)
}

// Load loads config values from file,
// fallback to load from environment variables if file is not found or failed to read
func Load(v *viper.Viper, configPath string) (LogConfig, error) {
	v.SetConfigFile(configPath)
	if err := v.ReadInConfig(); err != nil {
		log.WithError(err).Info("No config file found, loading config from environment variables")
		return LoadConfigFromEnv(v)
	}
	log.WithField("path", v.ConfigFileUsed()).Info("Config loaded from file")

	var instance LogConfig
	if err := v.Unmarshal(&instance); err != nil {
		return instance, err
	}

	return instance, nil
}

// LoadConfigFromEnv loads config values from environment variables
func LoadConfigFromEnv(v *viper.Viper) (LogConfig, error) {
	var instance LogConfig

	if err := v.Unmarshal(&instance); err != nil {
		return instance, err
	}

	err := envconfig.Process("", &instance)
	if err != nil {
		return instance, err
	}

	return instance, nil
}
