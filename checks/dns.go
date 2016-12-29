package checks

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/raintank/worldping-api/pkg/log"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"gopkg.in/raintank/schema.v1"
)

type DnsResult struct {
	Time       *float64 `json:"time"`    //time for resolving
	Ttl        *uint32  `json:"ttl"`     //ttl in  DNS response header
	AnswersLen *int     `json:"answers"` //number of Answer in Answers array in DNS response
	Error      *string  `json:"error"`
}

func (r *DnsResult) Metrics(t time.Time, check *m.CheckWithSlug) []*schema.MetricData {
	metrics := make([]*schema.MetricData, 0)
	if r.Time != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.dns.time", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.dns.time",
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
			Value: *r.Time,
		})
	}
	if r.Ttl != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.dns.ttl", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.dns.ttl",
			Interval: int(check.Frequency),
			Unit:     "s",
			Mtype:    "gauge",
			Time:     t.Unix(),
			Tags: []string{
				fmt.Sprintf("product: %s", check.Settings["product"]),
				fmt.Sprintf("endpoint:%s", check.Slug),
				fmt.Sprintf("monitor_type:%s", check.Type),
				fmt.Sprintf("probe:%s", probe.Self.Slug),
			},
			Value: float64(*r.Ttl),
		})
	}
	if r.AnswersLen != nil {
		metrics = append(metrics, &schema.MetricData{
			OrgId:    int(check.OrgId),
			Name:     fmt.Sprintf("worldping.%s.%s.%s.dns.answers", check.Settings["product"], check.Slug, probe.Self.Slug),
			Metric:   "worldping.dns.time",
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
			Value: float64(*r.AnswersLen),
		})
	}

	return metrics
}

func (dnsResult DnsResult) ErrorMsg() string {
	if dnsResult.Error != nil {
		return *dnsResult.Error
	} else {
		return ""
	}
}

type FunctionDNS struct {
	Product     string        `json:"product"`
	Hostname    string        `json:"hostname"`
	Servers     []string      `json:"servers"`
	ResolvfFile string        `json:"resolvfile"`
	Protocol    string        `json:"protocol"`
	Port        int64         `json:"port"`
	RecordType  uint16        `json:"recordtype"`
	Timeout     time.Duration `json:"timeout"`
}

var DNSRecordType = map[string]uint16{
	"A":    dns.TypeA,
	"AAAA": dns.TypeAAAA,
	"NS":   dns.TypeNS,
	"SOA":  dns.TypeSOA,
}

func getDNSServersFromFile(resolvconf string) (*dns.ClientConfig, error) {
	return dns.ClientConfigFromFile(resolvconf)
}

func NewFunctionDNS(settings map[string]interface{}) (*FunctionDNS, error) {
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
		return nil, errors.New("DNS: Empty hostname")
	}
	h, ok := hostname.(string)
	if !ok {
		return nil, errors.New("DNS: hostname must be string")
	}

	_servers, ok := settings["servers"]
	var servers []string
	if !ok {
		_resolvfFile, ok := settings["resolvfile"]
		if !ok {
			return nil, errors.New("Empty DNS File and DNS server list")
		}
		resolvfFile := _resolvfFile.(string)
		config, _err := getDNSServersFromFile(resolvfFile)
		if _err != nil {
			return nil, errors.New(fmt.Sprintf("Error getting DNS servers from file: %s with err: %s", resolvfFile, _err.Error()))
		}
		servers = config.Servers
	} else {
		s, ok := _servers.(string)
		if !ok {
			return nil, errors.New("DNS: servers list must be string")
		}
		servers = strings.Split(s, ",")
	}
	if len(servers) == 0 {
		return nil, errors.New(fmt.Sprintf("DNS: Invalid DNS servers list (comma seperated) %s", _servers))
	}

	_protocol, ok := settings["protocol"]
	protocol := "udp"
	if ok {
		protocol, ok = _protocol.(string)
		if !ok {
			return nil, errors.New("DNS: protocol must be string")
		}
		if protocol != "udp" && protocol != "tcp" {
			return nil, errors.New(fmt.Sprintf("DNS: Invalid Protocol %s", protocol))
		}
	}

	_port, ok := settings["port"]
	port := int64(53)
	if ok {
		_p, ok := _port.(float64)
		if !ok {
			return nil, errors.New("DNS: port must be int")
		}
		port = int64(_p)
		if port > 65555 || port < 0 {
			return nil, errors.New(fmt.Sprintf("DNS: Invalid port: %d", port))
		}
	}

	_recordtype, ok := settings["recordtype"]
	recordtype := DNSRecordType["A"]
	if ok {
		_r, ok := _recordtype.(string)
		if !ok {
			return nil, errors.New("DNS: recordtype must be string")
		}
		recordtype, ok = DNSRecordType[_r]
		if !ok {
			return nil, errors.New(fmt.Sprintf("DNS: Invalid Record Type: %s", _r))
		}
	}

	timeout, ok := settings["timeout"]
	if !ok {
		timeout = 5.0
	}
	_t, ok := timeout.(float64)
	if !ok {
		return nil, errors.New("DNS: timeout must be int")
	}
	t := int64(_t)
	return &FunctionDNS{Product: product, Hostname: h, Servers: servers, Protocol: protocol, Port: port, RecordType: recordtype, Timeout: time.Duration(t) * time.Second}, nil
}

func (p *FunctionDNS) Run() (CheckResult, error) {
	start := time.Now()
	t := 0.0
	ttl := uint32(0)
	answerslen := 0
	result := &DnsResult{}

	//Get result from the first success DNS server
	for _, server := range p.Servers {
		log.Debug("DNS: resolve DNS for %s with server: %s", p.Hostname, server)
		hostportStr := fmt.Sprintf("%s:%d", server, p.Port)

		var msg dns.Msg
		fullyQualifiedDomain := fmt.Sprintf("%s.", p.Hostname)
		msg.SetQuestion(fullyQualifiedDomain, p.RecordType)
		client := dns.Client{Net: p.Protocol}

		//rtt : only UDP return
		retmsg, _t, err := client.Exchange(&msg, hostportStr)
		if err != nil || retmsg == nil {
			log.Debug("DNS: Error resolve DNS for %s with server: %s err: %#v retmsg: %#v",
				p.Hostname, server, err, retmsg)
			continue
		}

		_t = time.Since(start)
		t = _t.Seconds() * 1000
		result.Time = &t

		if time.Since(start) > p.Timeout {
			return nil, errors.New(fmt.Sprintf("Timeout resolve DNS for %s with : %f", p.Hostname, _t.Seconds()))
		}
		ttl = retmsg.Answer[0].Header().Ttl
		result.Ttl = &ttl

		answerslen = len(retmsg.Answer)
		result.AnswersLen = &answerslen

		return result, nil
	}

	//All servers failed to resolve
	return nil, errors.New(fmt.Sprintf("Timeout resolve DNS for %s", p.Hostname))
}
