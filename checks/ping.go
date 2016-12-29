package checks

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/raintank/go-pinger"
	"github.com/raintank/worldping-api/pkg/log"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"gopkg.in/raintank/schema.v1"
)

const count = 5

var GlobalPinger *pinger.Pinger

func init() {
	GlobalPinger = pinger.NewPinger()
}

type PingResult struct {
	Loss   *float64 `json:"loss"`   //%
	Min    *float64 `json:"min"`    //ms
	Max    *float64 `json:"max"`    //ms
	Avg    *float64 `json:"avg"`    //ms
	Median *float64 `json:"median"` //middle of success
	Mdev   *float64 `json:"mdev"`   //
	Error  *string  `json:"error"`
}

func (r *PingResult) Metrics(t time.Time, check *m.CheckWithSlug) []*schema.MetricData {
	metrics := make([]*schema.MetricData, 0)
	if r.Loss != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.ping.loss", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.ping.loss",
			Interval: int(check.Frequency),
			Unit:     "percent",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Loss,
		})
	}
	if r.Min != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.ping.min", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.ping.min",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Min,
		})
	}
	if r.Max != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.ping.max", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.ping.max",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Max,
		})
	}
	if r.Median != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.ping.median", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.ping.median",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Median,
		})
	}
	if r.Mdev != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.ping.mdev", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.ping.mdev",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Mdev,
		})
	}
	if r.Avg != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.ping.mean", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.ping.mean",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Avg,
		})
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.ping.default", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.ping.default",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Avg,
		})
	}

	return metrics
}

func (pingResult PingResult) ErrorMsg() string {
	if pingResult.Error != nil {
		return *pingResult.Error
	} else {
		return ""
	}
}

type FunctionPing struct {
	Product  string        `json:"product"`
	Hostname string        `json:"hostname"`
	Timeout  time.Duration `json:"timeout"`
}

func NewFunctionPing(settings map[string]interface{}) (*FunctionPing, error) {
	_product, ok := settings["product"]
	if !ok {
		return nil, errors.New("Ping: Empty product name")
	}
	product, ok := _product.(string)
	if !ok {
		return nil, errors.New("Ping: product must be string")
	}

	hostname, ok := settings["hostname"]
	if !ok {
		return nil, errors.New("Ping: Empty Name")
	}
	h, ok := hostname.(string)

	if !ok {
		return nil, errors.New("Ping: hostname is not string")
	}

	timeout, ok := settings["timeout"]
	if !ok {
		timeout = float64(1)
	}
	_t, ok := timeout.(float64)
	if !ok {
		return nil, errors.New("Ping: timeout must be int64")
	}
	t := int64(_t)
	return &FunctionPing{Product: product, Hostname: h, Timeout: time.Duration(t) * time.Second}, nil
}

func (p *FunctionPing) Run() (CheckResult, error) {
	start := time.Now()
	deadline := time.Now().Add(p.Timeout)
	result := &PingResult{}

	ip, err := net.ResolveIPAddr("ip", p.Hostname)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error resolve ip addr from host: %s", p.Hostname))
	}
	if time.Since(start) > p.Timeout {
		return nil, errors.New(fmt.Sprintf("Timeout resolve ip addr from host: %s", p.Hostname))
	}

	log.Debug("Ip addr for host: %s is: %s", p.Hostname, ip.String())
	pingStatsChan, err := GlobalPinger.Ping(ip.String(), count, deadline)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error pinging ip addr :%s with error: %s", ip.String(), err.Error()))
	}

	pingStats := <-pingStatsChan

	if len(pingStats.Latency) == 0 || pingStats.Received == 0 {
		errStr := fmt.Sprintf("100% Loss while pinging %s", p.Hostname)
		return &PingResult{Error: &errStr}, nil
	}

	//Calculating
	//latency measurement
	measurement := make([]float64, len(pingStats.Latency))
	for key, value := range pingStats.Latency {
		measurement[key] = value.Seconds() * 1000
	}
	loss := float64((pingStats.Sent - pingStats.Received) * 100 / pingStats.Sent)
	result.Loss = &loss

	min := measurement[0]
	max := measurement[0]
	avg := 0.0
	tsum := 0.0
	tsum2 := 0.0
	for _, value := range measurement {
		tsum += value
		tsum2 += value * value
		if value > max {
			max = value
		}
		if value < min {
			min = value
		}
	}
	result.Min = &min
	result.Max = &max

	successCount := len(measurement)
	avg = tsum / float64(successCount)
	result.Avg = &avg

	mdev := (tsum2 / float64(successCount)) - (tsum/float64(successCount))*(tsum/float64(successCount))
	median := measurement[successCount/2]
	result.Mdev = &mdev
	result.Median = &median
	return result, nil
}
