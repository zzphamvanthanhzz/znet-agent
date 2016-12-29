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
			Name:     fmt.Sprintf("worldping.%s.%s.http.dns", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.dns",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.connect", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.connect",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.send", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.send",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.wait", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.wait",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.recv", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.recv",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.total", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.total",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Total,
		})
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.http.default", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.default",
			Interval: int(check.Frequency),
			Unit:     "ms",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.throughput", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.throughput",
			Interval: int(check.Frequency),
			Unit:     "B/s",
			Mtype:    "rate",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.dataLength", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.dataLength",
			Interval: int(check.Frequency),
			Unit:     "B",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
			Name:     fmt.Sprintf("worldping.%s.%s.http.statusCode", check.Slug, probe.Self.Slug),
			Metric:   "worldping.http.statusCode",
			Interval: int(check.Frequency),
			Unit:     "",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
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
	Host        string        `json:"hostname"`
	Path        string        `json:"path"`
	Port        int64         `json:"port"`
	Method      string        `json:"method"`
	Headers     string        `json:"headers"`     //delimiter: \n
	ExpectRegex string        `json:"expectregex"` //string wants to be appears (error: 0 ...)
	Body        string        `json:"body"`
	Timeout     time.Duration `json:"timeout"`
}

func NewFunctionHTTP(settings map[string]interface{}) (*FunctionHTTP, error) {
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
		t, ok = timeout.(int64)
		if !ok {
			return nil, errors.New("HTTP: timeout must be int")
		}
	}

	return &FunctionHTTP{Host: h, Path: p, Port: pt, Method: m, Headers: hds, ExpectRegex: r, Body: b, Timeout: time.Duration(t) * time.Second}, nil
}

func (p *FunctionHTTP) Run() (CheckResult, error) {
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
		msg := fmt.Sprintf("HTTP: Timeout resolving IP addr for %s", p.Host)
		result.Error = &msg
		return result, nil
	}

	url := fmt.Sprintf("http://%s:%d%s", addrs[0], p.Port, strings.Trim(p.Path, " "))
	fmt.Println(url)
	reqbody := bytes.NewReader([]byte(p.Body))
	request, err := http.NewRequest(p.Method, url, reqbody)
	if err != nil {
		msg := err.Error()
		result.Error = &msg
		return result, nil
	}
	if p.Headers != "" {
		b := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n" + p.Headers + "\r\n\r\n"))
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
	if request.Header.Get("Accept-Encoding") == "" {
		request.Header.Set("Accept-Encoding", "gzip")
	}
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
	connect := float64(time.Since(step).Seconds() * 1000)
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
	send := float64(time.Since(step).Seconds() * 1000)
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
	wait := float64(time.Since(step).Seconds() * 1000)
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
				break
			} else {
				msg := fmt.Sprintf("HTTP: Error reading body from conn: %s with err: %s", sockaddr, err.Error())
				result.Error = &msg
				return result, nil
			}
		}
		datasize += count
		if datasize >= Limit {
			break
		}
	}
	recv := float64(time.Since(step).Seconds() * 1000)
	total := float64(time.Since(start).Seconds() * 1000)
	result.Recv = &recv
	result.Total = &total
	if time.Now().Sub(deadline).Seconds() > 0.0 {
		msg := fmt.Sprintf("HTTP: Timeout after reading: %d bytes of body from conn: %s", datasize, sockaddr)
		result.Error = &msg
		return result, nil
	}

	var headerbyteBuffer bytes.Buffer
	datalength := float64(datasize)
	err = response.Header.Write(&headerbyteBuffer)
	if err == nil {
		datalength += float64(headerbyteBuffer.Len())
	}
	result.DataLength = &datalength

	throughput := float64(datasize) * 1000 * 8 / float64(recv) //bit/s
	result.Throughput = &throughput

	statuscode := float64(response.StatusCode)
	result.StatusCode = &statuscode
	if statuscode < 100 || statuscode >= 600 {
		msg := fmt.Sprintf("HTTP: Invalid status code %f", statuscode)
		result.Error = &msg
		return result, nil
	} else if statuscode != 200 {
		msg := fmt.Sprintf("HTTPS: Error code %f", statuscode)
		result.Error = &msg
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
			msg := "ExpectRegex not match"
			result.Error = &msg
			return result, nil
		}
	}

	return result, nil
}