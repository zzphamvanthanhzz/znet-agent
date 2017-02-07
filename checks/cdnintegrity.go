package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/raintank/worldping-api/pkg/log"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"gopkg.in/raintank/schema.v1"
)

type CDNINTEResult struct {
	DNS        *float64 `json:"dns"`        //DNS resolve time
	Connect    *float64 `json:"connect"`    //Dial to connect to host
	Send       *float64 `json:"send"`       //Write to connection
	Wait       *float64 `json:"wait"`       //Receive all header
	Recv       *float64 `json:"recv"`       //Receive configured size
	Total      *float64 `json:"total"`      //total time
	DataLength *float64 `json:"datalen"`    //
	Throughput *float64 `json:"throughput"` //data len / total time (bit/s)
	TotalLink  *float64 `json:"totallink"`
	Error      *string  `json:"error"`
}

//Link return by ZINGTV
type LinkDetail struct {
	Url  string `json:"url"`
	Size int64  `json:"size"`
}

//Result from CDN
type NodeDetails struct {
	Domain         string `json:"domain"`
	OriginalDomain string `json:"originalDomain"`
	IpAddress      string `json:"ipAddress"`
}

type CDNResult struct {
	Success     bool   `json:"success"`
	ErrorMsg    string `json:"errorMsg"`
	NodeDomains []NodeDetails
}

var (
	CDNEndpoint = "http://api.vcdn.vn/ird-restful-services"
	CDNPath     = "cdn/get-node-domains"
	CDNUser     = "g2static.api"
	CDNPass     = "uD61BMZRofhPUdeWV0LJ"
)

func (r *CDNINTEResult) Metrics(t time.Time, check *m.CheckWithSlug) []*schema.MetricData {
	metrics := make([]*schema.MetricData, 0)
	if r.DNS != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.dns", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.dns",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.connect", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.connect",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.send", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.send",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.wait", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.wait",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.recv", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.recv",
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
	if r.TotalLink != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.totallink", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.totallink",
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
	if r.Total != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.total", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.total",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.default", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.default",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.throughput", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.throughput",
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
			Name:     fmt.Sprintf("worldping.%s.%s.%s.cdnintegrity.dataLength", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.cdnintegrity.dataLength",
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

func (cdninteResult CDNINTEResult) ErrorMsg() string {
	if cdninteResult.Error != nil {
		return *cdninteResult.Error
	} else {
		return ""
	}
}

type FunctionCDNINTE struct {
	Product   string        `json:"product"`
	Host      string        `json:"hostname"`
	Timeout   time.Duration `json:"timeout"`
	ChunkSize int64         `json:"chunksize"`
	NumFile   int64         `json:"numfile"`
}

func NewFunctionCDNINTE(settings map[string]interface{}) (*FunctionCDNINTE, error) {
	_product, ok := settings["product"]
	if !ok {
		return nil, errors.New("CDNINTE: Empty product name")
	}
	product, ok := _product.(string)
	if !ok {
		return nil, errors.New("CDNINTE: product must be string")
	}

	hostname, ok := settings["hostname"]
	if !ok {
		return nil, errors.New("CDNINTE: Empty hostname")
	}
	h, ok := hostname.(string)
	if !ok {
		return nil, errors.New("CDNINTE: hostname must be string")
	}

	t := int64(5)
	timeout, ok := settings["timeout"]
	if ok {
		_t, ok := timeout.(float64)
		if !ok {
			return nil, errors.New("CDNINTE: timeout must be int")
		}
		t = int64(_t)
	}

	numfile := int64(NumFileLimit)
	nf, ok := settings["numfile"]
	if ok {
		_numfile, ok := nf.(float64)
		if !ok {
			return nil, errors.New("CDNINTE: numfile must be int")
		}
		numfile = int64(_numfile)
	}

	chunksize := int64(CDNLastBytesSize)
	cs, ok := settings["chunksize"]
	if ok {
		_chunksize, ok := cs.(float64)
		if !ok {
			return nil, errors.New("CDNINTE: chunksize must be int")
		}
		chunksize = int64(_chunksize)
		if chunksize%1024 != 0 {
			return nil, errors.New("CDNINTE: chunksize must divisor of 1024 (minimum chunk size each download)")
		}
	}

	return &FunctionCDNINTE{Product: product, Host: h, Timeout: time.Duration(t) * time.Second,
		NumFile: numfile, ChunkSize: chunksize}, nil
}

func (p *FunctionCDNINTE) Run() (CheckResult, error) {
	dns := float64(0)
	conn := float64(0)
	send := float64(0)
	wait := float64(0)
	recv := float64(0)
	total := float64(0)
	throughput := float64(0)
	datalength := float64(0)

	result := &CDNINTEResult{
		DNS:        &dns,
		Connect:    &conn,
		Send:       &send,
		Wait:       &wait,
		Recv:       &recv,
		Total:      &total,
		Throughput: &throughput,
		DataLength: &datalength,
	}
	productDomainMap := map[string][]NodeDetails{}
	remain := p.NumFile

	pRes, err := http.Get(p.Host)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("CDNINTE: Error creating CDNINTE check with err %s", err.Error()))
	}
	pBody, err := ioutil.ReadAll(pRes.Body)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("CDNINTE: Error reading product response body %s with err %s",
			p.Host, err.Error()))
	}
	pLinks := map[string][]LinkDetail{}
	err = json.Unmarshal(pBody, &pLinks)
	if err != nil {
		if err.Error() != "json: cannot unmarshal string into Go value of type main.LinkDetail" {
			return nil, errors.New(fmt.Sprintf("CDNINTE: Error parsing JSON from product response %s with err %s",
				p.Host, err.Error()))
		}
	}

	for _, grLinks := range pLinks {
		for _, lDetails := range grLinks {

			_url := lDetails.Url
			_size := lDetails.Size
			if _size < p.ChunkSize {
				continue
			}

			if _url == "" || _size == 0 {
				continue
			}
			u, err := url.Parse(_url)
			if err != nil {
				continue
			}

			if u.Scheme == "" {
				_url = fmt.Sprintf("http://%s", _url)
			}
			u, err = url.Parse(_url)
			if err != nil {
				continue
			}

			cdnDomainNodes, ok := productDomainMap[u.Host]
			if !ok {
				cUrl := fmt.Sprintf("%s/%s/%s", CDNEndpoint, CDNPath, u.Host)
				b := bytes.NewBuffer([]byte(""))
				cReq, err := http.NewRequest("GET", cUrl, b)
				cReq.SetBasicAuth(CDNUser, CDNPass)
				cReq.Header.Set("accept", "application/json")
				client := http.Client{}
				cRes, err := client.Do(cReq)
				if err != nil {
					return nil, errors.New(fmt.Sprintf("CDNINTE: Error getting domain nodes from CDN: %s/%s with error: %s",
						CDNEndpoint, CDNPath, err.Error()))
				}
				cBody, err := ioutil.ReadAll(cRes.Body)
				if err != nil {
					return nil, errors.New(fmt.Sprintf("CDNINTE: Error reading body of cdn response : %s/%s with error: %s",
						CDNEndpoint, CDNPath, err.Error()))
				}
				var cRessult CDNResult
				err = json.Unmarshal(cBody, &cRessult)
				if err != nil {
					return nil, errors.New(fmt.Sprintf("CDNINTE: Error unmarshal cdn response: %s/%s with error: %s",
						CDNEndpoint, CDNPath, err.Error()))
				}
				if cRessult.ErrorMsg != "" || cRessult.Success != true {
					return nil, errors.New(fmt.Sprintf("CDNINTE: Error from cdn response: %s/%s with error: %s",
						CDNEndpoint, CDNPath, cRessult.ErrorMsg))
				}
				productDomainMap[u.Host] = cRessult.NodeDomains
			}

			cdnDomainNodes, _ = productDomainMap[u.Host]
			if len(cdnDomainNodes) == 0 {
				return nil, errors.New(fmt.Sprintf("CDNINTE: Error from cdn %s/%s : empty node list for %s",
					CDNEndpoint, CDNPath, u.Host))
			}

			for _, cNode := range cdnDomainNodes {
				if remain == 0 {
					goto calculate
				}

				chkUrl := fmt.Sprintf("%s://%s/%s", u.Scheme, cNode.Domain, u.Path)
				log.Debug("Checking link is (%d): %s for host: %s with size: %d \n", p.NumFile-remain+1, chkUrl, u.Host, _size)
				settings := map[string]interface{}{}
				if u.Scheme == "http" {
					settings["product"] = p.Product
					settings["method"] = "GET"
					settings["hostname"] = cNode.Domain
					settings["port"] = interface{}(80.0)
					settings["path"] = u.Path
					settings["headers"] = fmt.Sprintf("Range: bytes=%d-", _size-p.ChunkSize)
					settings["getall"] = false
					settings["timeout"] = interface{}(p.Timeout.Seconds())
					check, err := NewFunctionHTTP(settings)
					if err != nil {
						continue
					}
					chkRet, err := check.Run()
					if err != nil {
						msg := fmt.Sprintf("CDNINTE: Error check  link %s for ori %s with err: %s",
							chkUrl, u.Host, err.Error())
						result.Error = &msg
						goto calculate
					}
					if chkRet.ErrorMsg() != "" {
						msg := fmt.Sprintf("CDNINTE: Error check  link %s for ori %s with err: %s",
							chkUrl, u.Host, chkRet.ErrorMsg())
						result.Error = &msg
						goto calculate
					}
					checkSlug := m.CheckWithSlug{}
					_retMetricsData := chkRet.Metrics(time.Now(), &checkSlug)
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
							if int64(m.Value) != p.ChunkSize {
								msg := fmt.Sprintf("CDNINTE: CDN size: %d diffrent from chunk size: %d",
									int64(m.Value), p.ChunkSize)
								result.Error = &msg
								remain--
								goto calculate
							}
						}
					}
					//Only calculated when success
					remain--
				} else {
					settings["product"] = p.Product
					settings["method"] = "GET"
					settings["hostname"] = cNode.Domain
					settings["port"] = interface{}(443.0)
					settings["path"] = u.Path
					settings["headers"] = fmt.Sprintf("Range: bytes=%d-", _size-p.ChunkSize)
					settings["getall"] = false
					settings["timeout"] = interface{}(p.Timeout.Seconds())
					check, err := NewFunctionHTTP(settings)
					if err != nil {
						continue
					}
					chkRet, err := check.Run()
					if err != nil {
						msg := fmt.Sprintf("CDNINTE: Error check  link %s for ori %s with err: %s",
							chkUrl, u.Host, err.Error())
						result.Error = &msg
						goto calculate
					}
					if chkRet.ErrorMsg() != "" {
						msg := fmt.Sprintf("CDNINTE: Error check  link %s for ori %s",
							chkUrl, u.Host, chkRet.ErrorMsg())
						result.Error = &msg
						goto calculate
					}
					checkSlug := m.CheckWithSlug{}
					_retMetricsData := chkRet.Metrics(time.Now(), &checkSlug)
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
							if int64(m.Value) != p.ChunkSize {
								msg := fmt.Sprintf("CDNINTE: CDN size: %d diffrent from chunk size: %d",
									int64(m.Value), p.ChunkSize)
								result.Error = &msg
								remain--
								goto calculate
							}
						}
					}
					//Only calculated when success
					remain--
				}

			}
		}
	}

calculate:
	totalLink := float64(p.NumFile - remain)
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
