package checks

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	u "net/url"

	"github.com/raintank/worldping-api/pkg/log"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"gopkg.in/raintank/schema.v1"
)

type HTTPResult struct {
	DNS        *float64 `json:"dns"`        //DNS resolve time
	Connect    *float64 `json:"connect"`    //Dial to connect to host
	Send       *float64 `json:"send"`       //Write to connection
	Wait       *float64 `json:"wait"`       //Receive all header
	Recv       *float64 `json:"recv"`       //Receive configured size
	Total      *float64 `json:"total"`      //total time
	DataLength *float64 `json:"datalen"`    //
	Throughput *float64 `json:"throughput"` //data len / total time (bit/s)
	StatusCode *float64 `json:"statuscode"`
	Error      *string  `json:"error"`
}

func (r *HTTPResult) Metrics(t time.Time, check *m.CheckWithSlug) []*schema.MetricData {
	metrics := make([]*schema.MetricData, 0)
	if r.DNS != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.dns", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.dns",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.connect", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.connect",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.send", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.send",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.wait", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.wait",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.recv", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.recv",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.total", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.total",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.default", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.default",
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
	if r.Throughput != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.throughput", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.throughput",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.dataLength", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.dataLength",
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
	if r.StatusCode != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.http.statusCode", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.statusCode",
			Interval: int(check.Frequency),
			Unit:     "",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.StatusCode,
		})
	}
	return metrics
}

func (httpResult HTTPResult) ErrorMsg() string {
	if httpResult.Error != nil {
		return *httpResult.Error
	} else {
		return ""
	}
}

type FunctionHTTP struct {
	Product      string        `json:"product"`
	Host         string        `json:"hostname"`
	Path         string        `json:"path"`
	Port         int64         `json:"port"`
	Method       string        `json:"method"`
	Headers      string        `json:"headers"`     //delimiter: \n
	ExpectRegex  string        `json:"expectregex"` //string wants to be appears (error: 0 ...)
	Body         string        `json:"body"`
	Timeout      time.Duration `json:"timeout"`
	GetAll       bool          `json:"getall"`
	RedirectTime int64         `json:"redirecttime"`
}

func NewFunctionHTTP(settings map[string]interface{}) (*FunctionHTTP, error) {
	_product, ok := settings["product"]
	if !ok {
		return nil, errors.New("HTTP: Empty product name")
	}
	product, ok := _product.(string)
	if !ok {
		return nil, errors.New("HTTP: product must be string")
	}

	hostname, ok := settings["hostname"]
	if !ok {
		return nil, errors.New("HTTP: Empty hostname")
	}
	h, ok := hostname.(string)
	if !ok {
		return nil, errors.New("HTTP: hostname must be string")
	}

	path, ok := settings["path"]
	p := "/"
	if ok {
		p, ok = path.(string)
		if !ok {
			return nil, errors.New("HTTP: path must be string")
		}
	}

	port, ok := settings["port"]
	pt := int64(80)
	if ok {
		_pt, ok := port.(float64)
		if !ok {
			return nil, errors.New("HTTP: port must be int")
		}
		pt = int64(_pt)
		if pt > 65555 || pt < 0 {
			return nil, errors.New("HTTP: invalid port")
		}
	}

	method, ok := settings["method"]
	m := "GET"
	if ok {
		m, ok = method.(string)
		if !ok {
			return nil, errors.New("HTTP: method must be string")
		}

		if m != "GET" && m != "POST" {
			return nil, errors.New("HTTP: invalid method")
		}
	}

	hds := ""
	headers, ok := settings["headers"]
	if ok {
		hds, ok = headers.(string)
		if !ok {
			return nil, errors.New("HTTP: headers must be string")
		}
	}

	r := ""
	regex, ok := settings["expectregex"]
	if ok {
		r, ok = regex.(string)
		if !ok {
			return nil, errors.New("HTTP: regex must be string")
		}
	}

	b := ""
	body, ok := settings["body"]
	if ok {
		b, ok = body.(string)
		if !ok {
			return nil, errors.New("HTTP: body must be string")
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

	a := false
	getall, ok := settings["getall"]
	if ok {
		a, ok = getall.(bool)
		if !ok {
			return nil, errors.New("HTTP: getall must be boolean")
		}
	}

	rd := int64(RedirectLimit)
	redirecttime, ok := settings["redirecttime"]
	if ok {
		_rd, ok := redirecttime.(float64)
		if !ok {
			return nil, errors.New("HTTP: redirecttime must be int")
		}
		rd = int64(_rd)
	}
	return &FunctionHTTP{Product: product, Host: h, Path: p, Port: pt, Method: m,
		Headers: hds, ExpectRegex: r, Body: b, Timeout: time.Duration(t) * time.Second,
		GetAll: a, RedirectTime: rd}, nil
}

func (p *FunctionHTTP) Run() (CheckResult, error) {
	if p.RedirectTime == 0 {
		msg := fmt.Sprintf("HTTP: redirect for : %s/%s over limit of %d", p.Host, p.Path, RedirectLimit)
		return nil, errors.New(msg)
	}

	start := time.Now()
	deadline := time.Now().Add(p.Timeout)
	result := &HTTPResult{}

	step := time.Now()
	addrs, err := net.LookupHost(p.Host)
	if err != nil {
		msg := err.Error()
		result.Error = &msg
		return result, nil
	}
	_dns := time.Since(step)
	dns := _dns.Seconds() * 1000
	result.DNS = &dns
	if _dns > p.Timeout {
		msg := fmt.Sprintf("HTTP: Timeout resolving IP addr for %s with DNS time: %f and Default timeout: %f",
			p.Host, _dns.Seconds(), p.Timeout.Seconds())
		result.Error = &msg
		return result, nil
	}

	url := fmt.Sprintf("http://%s:%d%s", addrs[0], p.Port, strings.Trim(p.Path, " "))
	reqbody := bytes.NewReader([]byte(p.Body))
	request, err := http.NewRequest(p.Method, url, reqbody)
	if err != nil {
		msg := err.Error()
		result.Error = &msg
		return result, nil
	}
	if p.Headers != "" {
		b := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n" + p.Headers + "\r\n\r\n"))
		_req, err := http.ReadRequest(b)
		if err != nil {
			msg := err.Error()
			result.Error = &msg
			return result, nil
		}
		_headers := _req.Header
		for key := range _headers {
			log.Debug("Config Header: %s with value: %s", key, _headers.Get(key))
			request.Header.Set(key, _headers.Get(key))
		}
	}
	// if request.Header.Get("Accept-Encoding") == "" {
	// 	request.Header.Set("Accept-Encoding", "gzip")
	// }
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "Mozilla/5.0")
	}

	//Always close connection
	// request.Header.Set("Host", p.Host) //By default Golang doesn't accept this header, it uses request.Host instead
	request.Host = p.Host
	request.Header.Set("Connection", "close")

	for k, v := range request.Header {
		log.Debug("Header: %s with value: %s", k, v)
	}

	sockaddr := fmt.Sprintf("%s:%d", addrs[0], p.Port)

	step = time.Now()
	conn, err := net.DialTimeout("tcp", sockaddr, p.Timeout)
	if err != nil {
		msg := err.Error()
		result.Error = &msg
		return result, nil
	}
	connect := time.Since(step).Seconds() * 1000
	result.Connect = &connect

	_connect := connect - float64(p.Timeout.Seconds()*1000)
	if _connect > 0 {
		msg := fmt.Sprintf("HTTP: Timeout creating connection to: %s", sockaddr)
		result.Error = &msg
		return result, nil
	}
	defer conn.Close()

	conn.SetDeadline(deadline)

	step = time.Now()
	err = request.Write(conn)
	if err != nil {
		msg := fmt.Sprintf("HTTP: Error writing to connection: %s with err: %s", sockaddr, err.Error())
		result.Error = &msg
		return result, nil
	}
	send := time.Since(step).Seconds() * 1000
	result.Send = &send
	if time.Now().Sub(deadline).Seconds() > 0 {
		msg := fmt.Sprintf("HTTP: Timeout after writing to connection: %s", sockaddr)
		result.Error = &msg
		return result, nil
	}

	//Wait will stop after all headers are read
	step = time.Now()
	response, err := http.ReadResponse(bufio.NewReader(conn), request)

	if err != nil {
		msg := fmt.Sprintf("HTTP: Error reading response from conn: %s with err: %s and response is: %s",
			sockaddr, err.Error())
		result.Error = &msg
		return result, nil
	}
	wait := time.Since(step).Seconds() * 1000
	result.Wait = &wait
	if time.Now().Sub(deadline).Seconds() > 0.0 {
		msg := fmt.Sprintf("HTTP: Timeout after reading headers from conn: %s", sockaddr)
		result.Error = &msg
	}

	//Read body
	step = time.Now()
	buf := make([]byte, 1024)
	var body bytes.Buffer
	datasize := 0
	for {
		count, err := response.Body.Read(buf)
		body.Write(buf[:count])
		if err != nil {
			if err == io.EOF {
				datasize += count
				log.Debug("HTTP: %s EOF with size: %d", p.Host, datasize)
				break
			} else {
				msg := fmt.Sprintf("HTTP: Error reading body from conn: %s with err: %s", sockaddr, err.Error())
				result.Error = &msg
				return result, nil
			}
		}
		datasize += count
		if !p.GetAll && datasize >= Limit {
			log.Debug("HTTP: %s%s Reach limit %f with size %f\n", p.Host, p.Path, float64(Limit), float64(datasize))
			break
		}
	}
	recv := time.Since(step).Seconds() * 1000
	total := time.Since(start).Seconds() * 1000
	result.Recv = &recv
	result.Total = &total
	if time.Now().Sub(deadline).Seconds() > 0.0 {
		msg := fmt.Sprintf("HTTP: Timeout after reading: %d bytes of body from conn: %s", datasize, sockaddr)
		result.Error = &msg
		return result, nil
	}

	datalength := float64(datasize)
	result.DataLength = &datalength

	throughput := float64(datasize) * 1000 * 8 / float64(recv) //bit/s
	result.Throughput = &throughput

	statuscode := float64(response.StatusCode)
	result.StatusCode = &statuscode
	if statuscode < 100 || statuscode >= 600 {
		msg := fmt.Sprintf("HTTP: Invalid status code %d from conn: %s", int64(statuscode), sockaddr)
		result.Error = &msg
		return result, nil
	} else if statuscode != 200 && statuscode != 302 && statuscode != 206 {
		msg := fmt.Sprintf("HTTP: Error code %d from conn: %s", int64(statuscode), sockaddr)
		result.Error = &msg
		return result, nil
	}
	log.Debug("HTTP: %s%s with size: %f\n", p.Host, p.Path, datalength)
	//Recursive for 302 code here
	if statuscode == 302 {
		redirectLink := response.Header.Get("Location")
		log.Debug("HTTP: Redirect from %s:%d%s to %s\n", p.Host, p.Port, p.Path, redirectLink)
		if redirectLink == "" {
			msg := fmt.Sprintf("HTTP: Empty Location in redirect Header from ori: %s:%d%s ", p.Host, p.Port, p.Path)
			result.Error = &msg
			return result, nil
		}

		link, err := u.Parse(redirectLink)
		if err != nil {
			msg := fmt.Sprintf("HTTP: Error parsing redirect link: %s from ori: %s:%d%s ",
				redirectLink, p.Host, p.Port, p.Path)
			result.Error = &msg
			return result, nil
		}
		if link.Scheme == "http" {
			settings := map[string]interface{}{
				"product":      p.Product,
				"hostname":     link.Host,
				"path":         link.Path,
				"port":         interface{}(80.0),
				"method":       "GET",
				"headers":      p.Headers,
				"expectRegex":  p.ExpectRegex,
				"body":         p.Body,
				"timeout":      interface{}(p.Timeout.Seconds()),
				"getall":       p.GetAll,
				"redirecttime": interface{}(float64(p.RedirectTime - 1)),
			}

			_p, err := NewFunctionHTTP(settings)
			if err != nil {
				msg := fmt.Sprintf("HTTP: Error creating new redirect check from %s:%d%s to %s:%d%s at redirect time %d with err: %s",
					p.Host, p.Port, p.Path, settings["hostname"], int64(settings["port"].(float64)), settings["path"],
					RedirectLimit-p.RedirectTime, err.Error())
				result.Error = &msg
				return result, nil
			}
			_result, err := _p.Run()
			if err != nil {
				msg := fmt.Sprintf("HTTP: Error in checking when redirect from %s:%d%s to %s:%d%s at redirect time %d with err: %s",
					p.Host, p.Port, p.Path, settings["hostname"], int64(settings["port"].(float64)), settings["path"],
					RedirectLimit-p.RedirectTime, err.Error())
				result.Error = &msg
				return result, nil
			}
			if _result.ErrorMsg() != "" {
				msg := fmt.Sprintf("HTTP: Error in checking when redirect from %s:%d%s to %s:%d%s at redirect time %d with err: %s",
					p.Host, p.Port, p.Path, settings["hostname"], int64(settings["port"].(float64)), settings["path"],
					RedirectLimit-p.RedirectTime, _result.ErrorMsg())
				result.Error = &msg
			}

			//Add all available check result into current result
			checkSlug := m.CheckWithSlug{}
			_retMetrics := _result.Metrics(time.Now(), &checkSlug)
			for _, _m := range _retMetrics {
				if _m.Metric == "worldping.http.dns" {
					dns = *(result.DNS) + _m.Value
					result.DNS = &dns
				} else if _m.Metric == "worldping.http.connect" {
					connect = *(result.Connect) + _m.Value
					result.Connect = &connect
				} else if _m.Metric == "worldping.http.send" {
					send = *(result.Send) + _m.Value
					result.Send = &send
				} else if _m.Metric == "worldping.http.wait" {
					wait = *(result.Wait) + _m.Value
					result.Wait = &wait
				} else if _m.Metric == "worldping.http.recv" {
					recv = *(result.Recv) + _m.Value
					result.Recv = &recv
				} else if _m.Metric == "worldping.http.total" {
					total = *(result.Total) + _m.Value
					result.Total = &total
				} else if _m.Metric == "worldping.http.default" {
					total = *(result.Total) + _m.Value
					result.Total = &total
				} else if _m.Metric == "worldping.http.throughput" { //If redirect, throughput and datalength is calculate for the last 200 code
					throughput = _m.Value
					result.Throughput = &throughput
				} else if _m.Metric == "worldping.http.dataLength" {
					datalength = _m.Value
					result.DataLength = &datalength
				}
			}
		} else if link.Scheme == "https" {
			settings := map[string]interface{}{
				"product":      p.Product,
				"hostname":     link.Host,
				"path":         link.Path,
				"port":         interface{}(443.0),
				"method":       "GET",
				"headers":      p.Headers,
				"expectRegex":  p.ExpectRegex,
				"body":         p.Body,
				"timeout":      interface{}(p.Timeout.Seconds()),
				"getall":       p.GetAll,
				"redirecttime": interface{}(float64(p.RedirectTime - 1)),
			}

			_p, err := NewFunctionHTTPS(settings)
			if err != nil {
				msg := fmt.Sprintf("HTTPS: Error creating new redirect check from %s:%d%s to %s:%d%s at redirect time %d with err: %s",
					p.Host, p.Port, p.Path, settings["hostname"], settings["port"], settings["path"],
					RedirectLimit-p.RedirectTime, err.Error())
				result.Error = &msg
				return result, nil
			}
			_result, err := _p.Run()
			if err != nil {
				msg := fmt.Sprintf("HTTPS: Error in checking when redirect from %s:%d%s to %s:%d%s at redirect time %d with err: %s",
					p.Host, p.Port, p.Path, settings["hostname"], settings["port"], settings["path"],
					RedirectLimit-p.RedirectTime, err.Error())
				result.Error = &msg
				return result, nil
			}
			if _result.ErrorMsg() != "" {
				msg := fmt.Sprintf("HTTPS: Error in checking when redirect from %s:%d%s to %s:%d%s at redirect time %d with err: %s",
					p.Host, p.Port, p.Path, settings["hostname"], settings["port"], settings["path"],
					RedirectLimit-p.RedirectTime, _result.ErrorMsg())
				result.Error = &msg
			}

			//Add all available check result into current result
			checkSlug := m.CheckWithSlug{}
			_retMetrics := _result.Metrics(time.Now(), &checkSlug)
			for _, _m := range _retMetrics {
				if _m.Metric == "worldping.https.dns" {
					dns = *(result.DNS) + _m.Value
					result.DNS = &dns
				} else if _m.Metric == "worldping.https.connect" {
					connect = *(result.Connect) + _m.Value
					result.Connect = &connect
				} else if _m.Metric == "worldping.https.send" {
					send = *(result.Send) + _m.Value
					result.Send = &send
				} else if _m.Metric == "worldping.https.wait" {
					wait = *(result.Wait) + _m.Value
					result.Wait = &wait
				} else if _m.Metric == "worldping.https.recv" {
					recv = *(result.Recv) + _m.Value
					result.Recv = &recv
				} else if _m.Metric == "worldping.https.total" {
					total = *(result.Total) + _m.Value
					result.Total = &total
				} else if _m.Metric == "worldping.https.default" {
					total = *(result.Total) + _m.Value
					result.Total = &total
				} else if _m.Metric == "worldping.https.throughput" { //If redirect, throughput and datalength is calculate for the last 200 code
					throughput = _m.Value
					result.Throughput = &throughput
				} else if _m.Metric == "worldping.https.dataLength" {
					datalength = _m.Value
					result.DataLength = &datalength
				}
			}
		}
		//Must return here
		return result, nil
	}

	if p.ExpectRegex != "" {
		reg, err := regexp.Compile(p.ExpectRegex)
		if err != nil {
			msg := err.Error()
			result.Error = &msg
			return result, nil
		}
		var bodydecode string
		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, err := gzip.NewReader(&body)
			if err != nil {
				msg := err.Error()
				result.Error = &msg
				return result, nil
			}
			bodydecodeBytes, err := ioutil.ReadAll(reader)
			if err != nil {
				msg := err.Error()
				result.Error = &msg
				return result, nil
			}
			bodydecode = string(bodydecodeBytes)
		default:
			bodydecode = body.String()
		}
		if !reg.MatchString(bodydecode) {
			msg := fmt.Sprintf("HTTP: ExpectRegex not match from conn: %s", sockaddr)
			result.Error = &msg
			return result, nil
		}
	}

	return result, nil
}
