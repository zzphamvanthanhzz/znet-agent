package checks

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"gopkg.in/raintank/schema.v1"
)

type HTTPSResult struct {
	DNS        *float64 `json:"dns"`        //DNS resolve time
	Connect    *float64 `json:"connect"`    //Dial to connect to host
	Send       *float64 `json:"send"`       //Write to connection
	Wait       *float64 `json:"wait"`       //Receive all header
	Recv       *float64 `json:"recv"`       //Receive configured size
	Total      *float64 `json:"total"`      //total time
	DataLength *float64 `json:"datalen"`    //
	Throughput *float64 `json:"throughput"` //data len / total time (bit/s)
	StatusCode *float64 `json:"statuscode"`
	Expiry     *float64 `json:"expiry"`
	Error      *string  `json:"error"`
}

func (r *HTTPSResult) Metrics(t time.Time, check *m.CheckWithSlug) []*schema.MetricData {
	metrics := make([]*schema.MetricData, 0)
	if r.DNS != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.dns", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.dns",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.connect", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.connect",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.send", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.send",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.wait", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.wait",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.recv", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.recv",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.total", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.total",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.default", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.default",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.throughput", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.throughput",
			Interval: int(check.Frequency),
			Unit:     "b/s",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.dataLength", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.dataLength",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.statusCode", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.statusCode",
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
	if r.Expiry != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.https.Expiry", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.https.expiry",
			Interval: int(check.Frequency),
			Unit:     "h",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: *r.Expiry,
		})
	}
	return metrics
}

func (httpsResult HTTPSResult) ErrorMsg() string {
	if httpsResult.Error != nil {
		return *httpsResult.Error
	} else {
		return ""
	}
}

type FunctionHTTPS struct {
	Product      string        `json:"product"`
	Host         string        `json:"hostname"`
	Path         string        `json:"path"`
	Port         int64         `json:"port"`
	ValidateCert bool          `json:"validatecert"`
	Method       string        `json:"method"`
	Headers      string        `json:"headers"`     //delimiter: \n
	ExpectRegex  string        `json:"expectregex"` //string wants to be appears (error: 0 ...)
	Body         string        `json:"body"`
	Timeout      time.Duration `json:"timeout"`
	GetAll       bool          `json:"getall"`
}

func NewFunctionHTTPS(settings map[string]interface{}) (*FunctionHTTPS, error) {
	_product, ok := settings["product"]
	if !ok {
		return nil, errors.New("DNS: Empty product name")
	}
	product, ok := _product.(string)
	if !ok {
		return nil, errors.New("DNS: product must be string")
	}

	hostname, ok := settings["hostname"]
	if !ok {
		return nil, errors.New("HTTPS: Empty hostname")
	}
	h, ok := hostname.(string)
	if !ok {
		return nil, errors.New("HTTPS: hostname must be string")
	}

	path, ok := settings["path"]
	p := "/"
	if ok {
		p, ok = path.(string)
		if !ok {
			return nil, errors.New("HTTPS: path must be string")
		}
	}

	port, ok := settings["port"]
	pt := int64(443)
	if ok {
		_pt, ok := port.(float64)
		if !ok {
			return nil, errors.New("HTTPS: port must be int")
		}
		pt = int64(_pt)
		if pt > 65555 || pt < 0 {
			return nil, errors.New("HTTPS: invalid port")
		}
	}

	validatecert, ok := settings["validatecert"]
	v := true
	if ok {
		v, ok = validatecert.(bool)
		if !ok {
			return nil, errors.New("HTTPS: validate cert must be bool")
		}
	}
	method, ok := settings["method"]
	m := "GET"
	if ok {
		m, ok = method.(string)
		if !ok {
			return nil, errors.New("HTTPS: method must be string")
		}

		if m != "GET" && m != "POST" {
			return nil, errors.New("HTTPS: invalid method")
		}
	}

	hds := ""
	headers, ok := settings["headers"]
	if ok {
		hds, ok = headers.(string)
		if !ok {
			return nil, errors.New("HTTPS: headers must be string")
		}
	}

	r := ""
	regex, ok := settings["expectregex"]
	if ok {
		r, ok = regex.(string)
		if !ok {
			return nil, errors.New("HTTPS: regex must be string")
		}
	}

	b := ""
	body, ok := settings["body"]
	if ok {
		b, ok = body.(string)
		if !ok {
			return nil, errors.New("HTTPS: body must be string")
		}
	}

	t := int64(5)
	timeout, ok := settings["timeout"]
	if ok {
		t, ok = timeout.(int64)
		if !ok {
			return nil, errors.New("HTTPS: timeout must be int")
		}
	}

	a := false
	getall, ok := settings["getall"]
	if ok {
		a, ok = getall.(bool)
		if !ok {
			return nil, errors.New("HTTPS: getall must be boolean")
		}
	}

	return &FunctionHTTPS{Product: product, Host: h, Path: p, Port: pt, ValidateCert: v,
		Method: m, Headers: hds, ExpectRegex: r, Body: b,
		Timeout: time.Duration(t) * time.Second, GetAll: a}, nil
}

func (p *FunctionHTTPS) Run() (CheckResult, error) {
	start := time.Now()
	deadline := time.Now().Add(p.Timeout)
	result := &HTTPSResult{}

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
		msg := fmt.Sprintf("HTTPS: Timeout resolving IP addr for %s", p.Host)
		result.Error = &msg
		return result, nil
	}

	url := fmt.Sprintf("http://%s:%d%s", addrs[0], p.Port, strings.Trim(p.Path, " "))
	reqbody := strings.NewReader(p.Body)
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
	request.Header.Set("Connection", "close")
	// request.Header.Set("Host", p.Host) //By default Golang doesn't accept this header, it uses request.Host instead
	request.Host = p.Host

	sockaddr := fmt.Sprintf("%s:%d", addrs[0], p.Port)

	tlsconfig := &tls.Config{
		InsecureSkipVerify: !p.ValidateCert,
		ServerName:         p.Host,
	}

	step = time.Now()
	tcpconn, err := net.DialTimeout("tcp", sockaddr, p.Timeout)
	if err != nil {
		msg := err.Error()
		result.Error = &msg
		return result, nil
	}
	connect := time.Since(step).Seconds() * 1000
	result.Connect = &connect
	if time.Now().Sub(deadline).Seconds() > 0 {
		msg := fmt.Sprintf("HTTPS: Timeout creating connection to: %s", sockaddr)
		result.Error = &msg
		return result, nil
	}
	tcpconn.SetDeadline(deadline)
	conn := tls.Client(tcpconn, tlsconfig)
	defer conn.Close()
	err = conn.Handshake()
	if err != nil {
		msg := err.Error()
		result.Error = &msg
		return result, nil
	}
	certs := conn.ConnectionState().PeerCertificates
	if certs == nil || len(certs) < 1 {
		secondsTileExpiry := float64(-1)
		result.Expiry = &secondsTileExpiry
	} else {
		timeTilExpiry := certs[0].NotAfter.Sub(time.Now())
		secondsTileExpiry := timeTilExpiry.Hours()
		result.Expiry = &secondsTileExpiry
	}

	step = time.Now()
	err = request.Write(conn)
	if err != nil {
		msg := fmt.Sprintf("HTTPS: Error writing to connection: %s with err: %s", sockaddr, err.Error())
		result.Error = &msg
		return result, nil
	}
	send := time.Since(step).Seconds() * 1000
	result.Send = &send
	if time.Now().Sub(deadline).Seconds() > 0 {
		msg := fmt.Sprintf("HTTPS: Timeout after writing to connection: %s", sockaddr)
		result.Error = &msg
		return result, nil
	}

	//Wait will stop after all headers are read
	step = time.Now()
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		msg := fmt.Sprintf("HTTPS: Error reading response from conn: %s with err: %s", sockaddr, err.Error())
		result.Error = &msg
		return result, nil
	}
	wait := time.Since(step).Seconds() * 1000
	result.Wait = &wait
	if time.Now().Sub(deadline).Seconds() > 0.0 {
		msg := fmt.Sprintf("HTTPS: Timeout after reading headers from conn: %s", sockaddr)
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
				msg := fmt.Sprintf("HTTPS: Error reading body from conn: %s with err: %s", sockaddr, err.Error())
				result.Error = &msg
				return result, nil
			}
		}
		datasize += count
		if !p.GetAll && datasize >= Limit {
			break
		}
	}
	recv := time.Since(step).Seconds() * 1000
	total := time.Since(start).Seconds() * 1000
	result.Recv = &recv
	result.Total = &total
	if time.Now().Sub(deadline).Seconds() > 0.0 {
		msg := fmt.Sprintf("HTTPS: Timeout after reading: %d bytes of body from conn: %s", datasize, sockaddr)
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
	fmt.Printf("Throughput for %s is %f with datasize: %d and recv time: %d \n",
		p.Host, throughput, datasize, recv)
	result.Throughput = &throughput

	statuscode := float64(response.StatusCode)
	result.StatusCode = &statuscode
	if statuscode < 100 || statuscode >= 600 {
		msg := fmt.Sprintf("HTTPS: Invalid status code %f from conn: %s", statuscode, sockaddr)
		result.Error = &msg
		return result, nil
	} else if statuscode != 200 {
		msg := fmt.Sprintf("HTTPS: Error code %f from conn: %s", statuscode, sockaddr)
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
			msg := fmt.Sprintf("HTTPS: ExpectRegex not match from conn: %s", sockaddr)
			result.Error = &msg
			return result, nil
		}
	}

	return result, nil
}
