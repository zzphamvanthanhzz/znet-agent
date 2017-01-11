package checks

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"gopkg.in/raintank/schema.v1"
)

type CLINKResult struct {
	DNS        *float64 `json:"dns"`        //DNS resolve time
	Connect    *float64 `json:"connect"`    //Dial to connect to host
	Send       *float64 `json:"send"`       //Write to connection
	Wait       *float64 `json:"wait"`       //Receive all header
	Recv       *float64 `json:"recv"`       //Receive configured size
	Total      *float64 `json:"total"`      //total time
	DataLength *float64 `json:"datalen"`    //
	Throughput *float64 `json:"throughput"` //data len / total time (bit/s)
	Error      *string  `json:"error"`
	TotalLink  *float64 `json:"totallink"` //number of child link
}

func (r *CLINKResult) Metrics(t time.Time, check *m.CheckWithSlug) []*schema.MetricData {
	metrics := make([]*schema.MetricData, 0)
	if r.DNS != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.dns", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.dns",
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
			Value: *r.DNS,
		})
	}
	if r.Connect != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.connect", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.connect",
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
	if r.Send != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.send", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.send",
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
			Value: *r.Send,
		})
	}
	if r.Wait != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.wait", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.wait",
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
			Value: *r.Wait,
		})
	}
	if r.Recv != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.recv", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.recv",
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
			Value: *r.Recv,
		})
	}
	if r.Total != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.total", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.total",
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
			Value: *r.Total,
		})
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.default", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.default",
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
			Value: *r.Total,
		})
	}
	if r.TotalLink != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.totallink", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.totallink",
			Interval: int(check.Frequency),
			Unit:     "links",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.TotalLink,
		})
	}
	if r.Throughput != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.throughput", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.throughput",
			Interval: int(check.Frequency),
			Unit:     "B/s",
			Mtype:    "rate",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Throughput,
		})
	}
	if r.DataLength != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.clink.dataLength", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.clink.dataLength",
			Interval: int(check.Frequency),
			Unit:     "B",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.DataLength,
		})
	}
	return metrics
}

func (staticResult CLINKResult) ErrorMsg() string {
	if staticResult.Error != nil {
		return *staticResult.Error
	} else {
		return ""
	}
}

type FunctionCLINK struct {
	Product     string        `json:"product"`
	Url         string        `json:"hostname"`
	Total       int64         `json:"total"`
	Method      string        `json:"method"`
	Headers     string        `json:"headers"`     //delimiter: \n
	ExpectRegex string        `json:"expectregex"` //string wants to be appears (error: 0 ...)
	Body        string        `json:"body"`
	Timeout     time.Duration `json:"timeout"`
}

func NewFunctionCLINK(settings map[string]interface{}) (*FunctionCLINK, error) {
	_product, ok := settings["product"]
	if !ok {
		return nil, errors.New("CLINK: Empty product name")
	}
	product, ok := _product.(string)
	if !ok {
		return nil, errors.New("CLINK: product must be string")
	}

	url, ok := settings["hostname"]
	if !ok {
		return nil, errors.New("CLINK: Empty url")
	}
	h, ok := url.(string)

	if !ok {
		return nil, errors.New("CLINK: url must be string")
	}

	total := int64(5)
	_total, ok := settings["total"]
	if ok {
		__total, ok := _total.(float64)
		if !ok {
			return nil, errors.New("CLINK: total must be int")
		}
		total = int64(__total)
	}

	method, ok := settings["method"]
	m := "GET"
	if ok {
		m, ok = method.(string)
		if !ok {
			return nil, errors.New("CLINK: method must be string")
		}

		if m != "GET" && m != "POST" {
			return nil, errors.New("CLINK: invalid method")
		}
	}

	hds := ""
	headers, ok := settings["headers"]
	if ok {
		hds, ok = headers.(string)
		if !ok {
			return nil, errors.New("CLINK: headers must be string")
		}
	}

	r := ""
	regex, ok := settings["expectregex"]
	if ok {
		r, ok = regex.(string)
		if !ok {
			return nil, errors.New("CLINK: regex must be string")
		}
	}

	b := ""
	body, ok := settings["body"]
	if ok {
		b, ok = body.(string)
		if !ok {
			return nil, errors.New("CLINK: body must be string")
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

	return &FunctionCLINK{Product: product, Total: total, Url: h, Method: m, Headers: hds,
		ExpectRegex: r, Body: b, Timeout: time.Duration(t) * time.Second}, nil
}

func (p *FunctionCLINK) Run() (CheckResult, error) {
	dns := float64(0)
	conn := float64(0)
	send := float64(0)
	wait := float64(0)
	recv := float64(0)
	total := float64(0)
	throughput := float64(0)
	datalength := float64(0)

	result := &CLINKResult{
		DNS:        &dns,
		Connect:    &conn,
		Send:       &send,
		Wait:       &wait,
		Recv:       &recv,
		Total:      &total,
		Throughput: &throughput,
		DataLength: &datalength,
	}

	remain := p.Total

	response, err := http.Get(p.Url)
	if err != nil {
		msg := fmt.Sprintf("CLINK: Error get content from url: %s with err: %s", p.Url, err.Error())
		return nil, errors.New(msg)
	}
	if response.StatusCode != 200 && response.StatusCode != 302 {
		msg := fmt.Sprintf("CLINK: Error code from url: %s with err: %s", p.Url, err.Error())
		return nil, errors.New(msg)
	}
	bytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		msg := fmt.Sprintf("CLINK: Error reading body from : %s with err: %s", p.Url, err.Error())
		return nil, errors.New(msg)
	}
	body := string(bytes)
	linkList := strings.Split(body, "\n")
	if len(linkList) == 0 {
		msg := fmt.Sprintf("CLINK: Empty body from url: %s", p.Url)
		return nil, errors.New(msg)
	}

	for _, link := range linkList {
		if remain == 0 {
			break
		}

		_link, err := url.Parse(link)
		if err != nil {
			msg := fmt.Sprintf("CLINK: Error parsing child link: %s with err: %s", link, err.Error())
			result.Error = &msg
			break
		}

		if _link.Scheme == "http" {
			settings := map[string]interface{}{}
			settings["product"] = p.Product
			settings["method"] = "GET"
			settings["getall"] = false
			settings["hostname"] = _link.Host
			settings["port"] = interface{}(80.0)
			settings["timeout"] = interface{}(p.Timeout.Seconds())
			settings["path"] = fmt.Sprintf("%s?%s", _link.Path, _link.RawQuery)
			check, err := NewFunctionHTTP(settings)
			if err != nil {
				msg := fmt.Sprintf("CLINK: Error creating HTTP for child link: %s with err: %s", link, err.Error())
				result.Error = &msg
				break
			}
			ret, err := check.Run()
			if err != nil {
				msg := fmt.Sprintf("CLINK: Error get child link: %s with error: %s", link, err.Error())
				result.Error = &msg
				break
			}
			if ret.ErrorMsg() != "" {
				msg := fmt.Sprintf("CLINK: Error get child link: %s with error: %s", link, ret.ErrorMsg())
				result.Error = &msg
				break
			}
			checkSlug := m.CheckWithSlug{}
			_retMetricsData := ret.Metrics(time.Now(), &checkSlug)
			for _, m := range _retMetricsData {
				if m.Metric == "worldping.http.dns" {
					dns := *(result.DNS) + m.Value
					result.DNS = &dns
				} else if m.Metric == "worldping.http.connect" {
					conn := *(result.Connect) + m.Value
					result.Connect = &conn
				} else if m.Metric == "worldping.http.send" {
					send := *(result.Send) + m.Value
					result.Send = &send
				} else if m.Metric == "worldping.clink.wait" {
					wait := *(result.Wait) + m.Value
					result.Wait = &wait
				} else if m.Metric == "worldping.http.recv" {
					recv := *(result.Recv) + m.Value
					result.Recv = &recv
				} else if m.Metric == "worldping.http.total" {
					total := *(result.Total) + m.Value
					result.Total = &total
				} else if m.Metric == "worldping.http.default" {
					total := *(result.Total) + m.Value
					result.Total = &total
				} else if m.Metric == "worldping.http.throughput" {
					throughput := *(result.Throughput) + m.Value
					result.Throughput = &throughput
				} else if m.Metric == "worldping.http.dataLength" {
					dataLen := *(result.DataLength) + m.Value
					result.DataLength = &dataLen
				}
			}
			//Only calculate if cussess
			remain--
		} else if _link.Scheme == "https" {
			settings := map[string]interface{}{}
			settings["product"] = p.Product
			settings["method"] = "GET"
			settings["getall"] = false
			settings["hostname"] = _link.Host
			settings["port"] = interface{}(443.0)
			settings["timeout"] = interface{}(p.Timeout.Seconds())
			settings["path"] = fmt.Sprintf("%s?%s", _link.Path, _link.RawQuery)
			check, err := NewFunctionHTTPS(settings)
			if err != nil {
				msg := fmt.Sprintf("CLINK: Error creating HTTP for child link: %s with err: %s", link, err.Error())
				result.Error = &msg
				break
			}
			ret, err := check.Run()
			if err != nil {
				msg := fmt.Sprintf("CLINK: Error get child link: %s with error: %s", link, err.Error())
				result.Error = &msg
				break
			}
			if ret.ErrorMsg() != "" {
				msg := fmt.Sprintf("CLINK: Error get child link: %s with error: %s", link, ret.ErrorMsg())
				result.Error = &msg
				break
			}
			checkSlug := m.CheckWithSlug{}
			_retMetricsData := ret.Metrics(time.Now(), &checkSlug)
			for _, m := range _retMetricsData {
				if m.Metric == "worldping.https.dns" {
					dns := *(result.DNS) + m.Value
					result.DNS = &dns
				} else if m.Metric == "worldping.https.connect" {
					conn := *(result.Connect) + m.Value
					result.Connect = &conn
				} else if m.Metric == "worldping.https.send" {
					send := *(result.Send) + m.Value
					result.Send = &send
				} else if m.Metric == "worldping.https.wait" {
					wait := *(result.Wait) + m.Value
					result.Wait = &wait
				} else if m.Metric == "worldping.https.recv" {
					recv := *(result.Recv) + m.Value
					result.Recv = &recv
				} else if m.Metric == "worldping.https.total" {
					total := *(result.Total) + m.Value
					result.Total = &total
				} else if m.Metric == "worldping.https.default" {
					total := *(result.Total) + m.Value
					result.Total = &total
				} else if m.Metric == "worldping.https.throughput" {
					throughput := *(result.Throughput) + m.Value
					result.Throughput = &throughput
				} else if m.Metric == "worldping.https.dataLength" {
					dataLen := *(result.DataLength) + m.Value
					result.DataLength = &dataLen
				}
			}
			//Only calculate if cussess
			remain--
		}
	}

	totalLink := float64(p.Total - remain)
	result.TotalLink = &totalLink

	dns = *result.DNS / totalLink
	result.DNS = &dns
	conn = *result.Connect / totalLink
	result.Connect = &conn
	send = *result.Send / totalLink
	result.Send = &send
	wait = *result.Wait / totalLink
	result.Wait = &wait
	recv = *result.Recv / totalLink
	result.Recv = &recv
	total = *result.Total / totalLink
	result.Total = &total
	datalength = *result.DataLength / totalLink
	result.DataLength = &datalength
	throughput = *result.Throughput / totalLink
	result.Throughput = &throughput

	return result, nil
}
