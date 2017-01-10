package checks

import (
	"errors"
	"fmt"
	"net"
	"time"

	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"gopkg.in/raintank/schema.v1"
)

type TCPResult struct {
	Loss    *float64 `json:"loss"`    //%
	Min     *float64 `json:"min"`     //ms
	Max     *float64 `json:"max"`     //ms
	Avg     *float64 `json:"avg"`     //ms
	Median  *float64 `json:"median"`  //middle of success
	Mdev    *float64 `json:"mdev"`    //
	Connect *float64 `json:"connect"` //Dial to connect to host
	Error   *string  `json:"error"`
}

func (r *TCPResult) Metrics(t time.Time, check *m.CheckWithSlug) []*schema.MetricData {
	metrics := make([]*schema.MetricData, 0)
	if r.Loss != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.loss", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.loss",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.min", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.min",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.max", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.max",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.median", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.median",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.mdev", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.mdev",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.mean", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.mean",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.default", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.default",
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
	if r.Connect != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.tcp.connect", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.tcp.connect",
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
			Value: *r.Connect,
		})
	}
	return metrics
}

func (httpResult TCPResult) ErrorMsg() string {
	if httpResult.Error != nil {
		return *httpResult.Error
	} else {
		return ""
	}
}

type FunctionTCP struct {
	Product string        `json:"product"`
	Host    string        `json:"hostname"`
	Ip      string        `json:"ip"`
	Port    int64         `json:"port"`
	Timeout time.Duration `json:"timeout"`
}

func NewFunctionTCP(settings map[string]interface{}) (*FunctionTCP, error) {
	_product, ok := settings["product"]
	if !ok {
		return nil, errors.New("TCP: Empty product name")
	}
	product, ok := _product.(string)
	if !ok {
		return nil, errors.New("TCP: product must be string")
	}

	hostname, ok := settings["hostname"]
	if !ok {
		return nil, errors.New("TCP: Empty hostname")
	}
	h, ok := hostname.(string)
	if !ok {
		return nil, errors.New("TCP: hostname must be string")
	}

	ip, ok := settings["ip"]
	if !ok {
		return nil, errors.New("TCP: Empty ip")
	}
	p, ok := ip.(string)
	if !ok {
		return nil, errors.New("TCP: ip must be string")
	}

	port, ok := settings["port"]
	pt := int64(80)
	if ok {
		_pt, ok := port.(float64)
		if !ok {
			return nil, errors.New("TCP: port must be int")
		}
		pt = int64(_pt)
		if pt > 65555 || pt < 0 {
			return nil, errors.New("TCP: invalid port")
		}
	}

	t := int64(5)
	timeout, ok := settings["timeout"]
	if ok {
		_t, ok := timeout.(float64)
		if !ok {
			return nil, errors.New("HTTP: timeout must be int")
		}
		t = int64(_t)
	}

	return &FunctionTCP{Product: product, Host: h, Ip: p, Port: pt, Timeout: time.Duration(t) * time.Second}, nil
}

func (p *FunctionTCP) Run() (CheckResult, error) {
	loss := float64(0)
	min := float64(0)
	max := float64(0)
	mean := float64(0)
	mdev := float64(0)
	median := float64(0)
	connect := float64(0)

	result := &TCPResult{
		Loss:    &loss,
		Min:     &min,
		Max:     &max,
		Median:  &median,
		Mdev:    &mdev,
		Avg:     &mean,
		Connect: &connect,
	}
	sockaddr := fmt.Sprintf("%s:%d", p.Ip, p.Port)

	settings := map[string]interface{}{}
	settings["product"] = p.Product
	settings["hostname"] = p.Ip
	pingFunc, err := NewFunctionPing(settings)
	if err != nil {
		msg := fmt.Sprintf("TCP: Error create ping check to sock: %s with err: %s", sockaddr, err.Error())
		return nil, errors.New(msg)
	}
	pingRet, err := pingFunc.Run()
	if err != nil {
		msg := fmt.Sprintf("TCP: Error create ping check to sock: %s with err: %s", sockaddr, err.Error())
		return nil, errors.New(msg)
	}
	checkSlug := m.CheckWithSlug{}
	pingMetrics := pingRet.Metrics(time.Now(), &checkSlug)
	for _, m := range pingMetrics {
		if m.Metric == "worldping.ping.loss" {
			loss = m.Value
		} else if m.Metric == "worldping.ping.min" {
			min = m.Value
		} else if m.Metric == "worldping.ping.max" {
			max = m.Value
		} else if m.Metric == "worldping.ping.median" {
			median = m.Value
		} else if m.Metric == "worldping.ping.mdev" {
			mdev = m.Value
		} else if m.Metric == "worldping.ping.mean" {
			mean = m.Value
		}
	}
	if pingRet.ErrorMsg() != "" {
		msg := fmt.Sprintf("TCP: Error with ping to sock: %s with err: %s", sockaddr, pingRet.ErrorMsg())
		result.Error = &msg
	}
	step := time.Now()
	_, err = net.DialTimeout("tcp", sockaddr, p.Timeout)
	if err != nil {
		msg := fmt.Sprintf("TCP: Error connect to sock: %s with err: %s", sockaddr, err.Error())
		result.Error = &msg
		return result, nil
	}
	connTime := float64(time.Since(step).Seconds() * 1000)
	result.Connect = &connTime

	return result, nil
}
