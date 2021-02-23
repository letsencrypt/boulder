package observer

import (
	"time"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/observer/plugins"
	"github.com/prometheus/client_golang/prometheus"
)

type monitor struct {
	name     string
	period   time.Duration
	timeout  time.Duration
	pluginIs string
	probe    plugins.Plugin
	logger   blog.Logger
	metric   prometheus.Registerer
}

func (m monitor) start() *time.Ticker {
	ticker := time.NewTicker(m.period)
	go func() {
		for {
			select {
			case tick := <-ticker.C:
				success, took := m.probe.Do(tick, m.timeout)
				statTotalObservations.WithLabelValues(m.pluginIs, m.name).Add(1)
				if !success {
					statTotalErrors.WithLabelValues(m.pluginIs, m.name).Add(1)
					m.logger.Infof("%s monitor %q failed while taking:=%s", m.pluginIs, m.name, took.String())
					return
				}
				m.logger.Infof("%s monitor %q succeeded while taking:=%s", m.pluginIs, m.name, took.String())
			}
		}
	}()
	return ticker
}

func (m monitor) New(c MonConf, log blog.Logger, prom prometheus.Registerer, t int) *monitor {
	if c.Timeout == 0 {
		c.Timeout = t
	}
	plugin, _ := plugins.GetPluginConf(c.Settings, c.Plugin.Path, c.Plugin.Name)
	m.name = plugin.GetMonitorName()
	m.period = time.Duration(c.Period * 1000000000)
	m.timeout = time.Duration(c.Timeout * 1000000000)
	m.pluginIs = c.Plugin.Name
	m.probe = plugin.AsProbe()
	m.logger = log
	m.metric = prom
	return &m
}
