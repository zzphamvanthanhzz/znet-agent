package scheduler

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/raintank/worldping-api/pkg/log"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/zzphamvanthanhzz/znet-agent/checks"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"github.com/zzphamvanthanhzz/znet-agent/publisher"
	"gopkg.in/raintank/schema.v1"
)

type checkFunction interface {
	Run() (checks.CheckResult, error)
}

type CheckInstance struct {
	Ticker      *time.Ticker
	Exec        checkFunction
	Check       *m.CheckWithSlug
	State       m.CheckEvalResult
	LastRun     time.Time
	StateChange time.Time
	LastError   string
	sync.Mutex
}

func NewCheckInstance(c *m.CheckWithSlug, healthy bool) (*CheckInstance, error) {
	log.Debug(fmt.Sprintf("NewCheckInstance with: %#v and healthy:  %#v", c, healthy))
	checkfunc, err := GetCheck(c.Type, c.Settings)
	if err != nil {
		log.Error(3, "Error creating new check Instance with err %s", err.Error())
		return nil, err
	}
	checkInstance := &CheckInstance{
		Exec:  checkfunc,
		State: m.EvalResultUnknown,
		Check: c,
	}
	if healthy {
		go checkInstance.Run()
	}
	return checkInstance, nil
}

func (i *CheckInstance) Update(c *m.CheckWithSlug, healthy bool) error {
	checkfunc, err := GetCheck(c.Type, c.Settings)
	if err != nil {
		return err
	}

	i.Lock()
	if i.Ticker != nil{
		i.Ticker.Stop()
	}
	i.Check = c
	i.Exec = checkfunc
	i.Unlock()
	if healthy {
		go i.Run()
	}
	log.Debug("Complete CheckInstance Update %#v", c)
	return nil
}

func (i *CheckInstance) Stop() {
	i.Lock()
	if i.Ticker != nil {
		i.Ticker.Stop()
	}
	i.Unlock()
}

func (i *CheckInstance) Run() {
	i.Lock()
	i.Ticker = time.NewTicker(time.Duration(i.Check.Frequency) * time.Second)
	i.Unlock()
	for t := range i.Ticker.C {
		log.Debug("Run check %s for hostname: %s", i.Check.Type, i.Check.Settings["hostname"])
		i.run(t)
	}
}

func (i *CheckInstance) run(t time.Time) {
	log.Info(fmt.Sprintf("Run check %s at %s", i.Check.Type, t.String()))
	checkRet, err := i.Exec.Run()
	if err != nil {
		log.Error(3, "Error running check : %s at: %s with err: %s", i.Check.Type, t.String(), err.Error())
		return
	}

	desc := fmt.Sprintf("for %s of %s", i.Check.Type, i.Check.Slug)
	var metrics []*schema.MetricData
	//Metrics
	metrics = checkRet.Metrics(t, i.Check)
	log.Debug("got %d metrics %s", len(metrics), desc)

	//Event
	newState := m.EvalResultOK
	if msg := checkRet.ErrorMsg(); msg != "" {
		log.Debug("Failed check %s with msg %s", desc, msg)
		newState = m.EvalResultCrit
		//only fire event on state changed or error message changed
		//or error continue for over 5mins
		if (i.State != newState) || (i.LastError != msg) || (time.Since(i.StateChange) > time.Minute*5) {
			i.StateChange = time.Now()
			i.State = newState
			i.LastError = msg

			//Fire event
			log.Info("Error %s ", desc)
			event := schema.ProbeEvent{
				EventType: "monitor_state",
				OrgId:     i.Check.OrgId,
				Severity:  "ERROR",
				Source:    "monitor_collector",
				Timestamp: t.UnixNano() / int64(time.Millisecond),
				Message:   msg,
				Tags: map[string]string{
					"product":      i.Check.Settings["product"].(string),
					"endpoint":     i.Check.Slug,
					"collector":    probe.Self.Slug,
					"monitor_type": string(i.Check.Type),
				},
			}
			publisher.Publisher.AddEvent(&event)
		}
	} else {
		i.State = newState
		i.StateChange = time.Now()
		//send OK event.
		log.Info("%s is now in OK state", desc)
		event := schema.ProbeEvent{
			EventType: "monitor_state",
			OrgId:     i.Check.OrgId,
			Severity:  "OK",
			Source:    "monitor_collector",
			Timestamp: t.UnixNano() / int64(time.Millisecond),
			Message:   "Monitor now Ok.",
			Tags: map[string]string{
				"product":      i.Check.Settings["product"].(string),
				"endpoint":     i.Check.Slug,
				"collector":    probe.Self.Slug,
				"monitor_type": string(i.Check.Type),
			},
		}
		publisher.Publisher.AddEvent(&event)
	}

	// set ok_state, error_state metrics.
	okState := 0.0
	errState := 0.0
	if i.State == m.EvalResultCrit {
		errState = 1
	} else {
		okState = 1
	}
	metrics = append(metrics, &schema.MetricData{
		OrgId:    int(i.Check.OrgId),
		Name:     fmt.Sprintf("worldping.%s.%s.%s.%s.ok_state", i.Check.Settings["product"], i.Check.Slug, probe.Self.Slug, i.Check.Type),
		Metric:   fmt.Sprintf("worldping.%s.ok_state", i.Check.Type),
		Interval: int(i.Check.Frequency),
		Unit:     "state",
		Mtype:    "gauge",
		Time:     t.Unix(),
		Tags: []string{
			fmt.Sprintf("product: %s", i.Check.Settings["product"]),
			fmt.Sprintf("endpoint:%s", i.Check.Slug),
			fmt.Sprintf("monitor_type:%s", i.Check.Type),
			fmt.Sprintf("probe:%s", probe.Self.Slug),
		},
		Value: okState,
	}, &schema.MetricData{
		OrgId:    int(i.Check.OrgId),
		Name:     fmt.Sprintf("worldping.%s.%s.%s.%s.error_state", i.Check.Settings["product"], i.Check.Slug, probe.Self.Slug, i.Check.Type),
		Metric:   fmt.Sprintf("worldping.%s.error_state", i.Check.Type),
		Interval: int(i.Check.Frequency),
		Unit:     "state",
		Mtype:    "gauge",
		Time:     t.Unix(),
		Tags: []string{
			fmt.Sprintf("product: %s", i.Check.Settings["product"]),
			fmt.Sprintf("endpoint:%s", i.Check.Slug),
			fmt.Sprintf("monitor_type:%s", i.Check.Type),
			fmt.Sprintf("probe:%s", probe.Self.Slug),
		},
		Value: errState,
	})

	for _, m := range metrics {
		m.SetId() //
	}

	//publish metrics to TSDB
	publisher.Publisher.Add(metrics)
}

type Scheduler struct {
	sync.RWMutex
	Check       map[int64]*CheckInstance
	HealthHosts []string
	Healthy     bool
}

func New(healthHostStr string) *Scheduler {
	healthHosts := make([]string, 0)
	for _, hhost := range strings.Split(healthHostStr, ",") {
		healthHosts = append(healthHosts, strings.TrimSpace(hhost))
	}
	return &Scheduler{
		Check:       make(map[int64]*CheckInstance),
		HealthHosts: healthHosts,
	}
}

func (s *Scheduler) Close() {
	s.Lock()
	for _, c := range s.Check {
		c.Stop()
	}
	s.Check = make(map[int64]*CheckInstance, 0)
	s.Unlock()
}

func (s *Scheduler) Refresh(checks []*m.CheckWithSlug) {
	seencheck := make(map[int64]bool)
	s.Lock()
	log.Debug("Refresh Agent with checks size: %d", len(checks))
	for _, check := range checks {
		if !check.Enabled {
			continue
		}
		if oldCheck, ok := s.Check[check.Id]; ok {
			log.Debug("Update check instance: %s for %s with checkId %d and endpointId %d",
				oldCheck.Check.Type, oldCheck.Check.Settings["hostname"], check.Id, check.EndpointId)
			err := oldCheck.Update(check, s.Healthy)
			if err != nil {
				log.Error(3, "Error updating check id: %d of type: %d with error %s", check.Id, check.Type, err.Error())
				oldCheck.Stop()
				delete(s.Check, check.Id)
			}
			seencheck[check.Id] = true
		} else {
			log.Debug("Create new check instance: %s for %s with checkId %d and endpointId %d",
				check.Type, check.Settings["hostname"], check.Id, check.EndpointId)
			newCheck, err := NewCheckInstance(check, s.Healthy)
			if err != nil {
				log.Error(3, "Error creating new check with error %s", err.Error())
			} else {
				s.Check[check.Id] = newCheck
				seencheck[check.Id] = true
			}
		}
	}

	for id, check := range s.Check {
		if _, ok := seencheck[id]; !ok {
			log.Info("Stop check id: %d", id)
			check.Stop()
			delete(s.Check, id)
		}
	}
	log.Debug("Finish refreshing: ")
	s.Unlock()
}

func (s *Scheduler) Create(check *m.CheckWithSlug) {
	s.Lock()
	if existingCheck, ok := s.Check[check.Id]; ok {
		log.Debug("Create 2: %#v", check)
		existingCheck.Stop()
		delete(s.Check, check.Id)
	}
	c, err := NewCheckInstance(check, s.Healthy)
	if err != nil {
		log.Error(3, "Error create new check %d of type: %d", check.Id, check.Type)
	} else {
		s.Check[check.Id] = c
	}
	s.Unlock()
}
func (s *Scheduler) Update(check *m.CheckWithSlug) {
	s.Lock()
	if existingCheck, ok := s.Check[check.Id]; !ok {
		c, err := NewCheckInstance(check, s.Healthy)
		if err != nil {
			log.Error(3, "Error create new check %d of type: %s with err: %s",
				check.Id, check.Type, err.Error())
		} else {
			s.Check[check.Id] = c
		}
	} else {
		err := existingCheck.Update(check, s.Healthy)
		if err != nil {
			log.Error(3, "Error update check: %d of type: %d", check.Id, check.Type)
			existingCheck.Stop()
			delete(s.Check, check.Id)
		}
	}
	s.Unlock()
}
func (s *Scheduler) Remove(check *m.CheckWithSlug) {
	s.Lock()
	if existingCheck, ok := s.Check[check.Id]; !ok {
		log.Error(3, "Error delete check: %d of type: %d", check.Id, check.Type)
	} else {
		existingCheck.Stop()
		delete(s.Check, check.Id)
	}
	s.Unlock()
}
func GetCheck(checkType m.CheckType, settings map[string]interface{}) (checkFunction, error) {
	switch checkType {
	case m.PING_CHECK:
		return checks.NewFunctionPing(settings)
	case m.DNS_CHECK:
		return checks.NewFunctionDNS(settings)
	case m.HTTP_CHECK:
		return checks.NewFunctionHTTP(settings)
	case m.HTTPS_CHECK:
		return checks.NewFunctionHTTPS(settings)
	case m.STATIC_CHECK:
		return checks.NewFunctionSTATIC(settings)
	case m.CLINK_CHECK:
		return checks.NewFunctionCLINK(settings)
	case m.TCP_CHECK:
		return checks.NewFunctionTCP(settings)
	case m.CDNINTEGRITY_CHECK:
		return checks.NewFunctionCDNINTE(settings)
	default:
		return nil, fmt.Errorf("Invalid type of check")
	}
}
