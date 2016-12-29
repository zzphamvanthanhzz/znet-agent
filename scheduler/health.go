package scheduler

import (
	"sync"
	"time"

	"github.com/raintank/worldping-api/pkg/log"
	"github.com/zzphamvanthanhzz/znet-agent/checks"
)

func (s *Scheduler) CheckHealth() {
	tickers := time.NewTicker(time.Duration(30) * time.Second)

	laststate := 1
	var wg sync.WaitGroup
	for t := range tickers.C {
		hcheckrets := make(chan int, len(s.HealthHosts))
		for _, _h := range s.HealthHosts {
			log.Info("CheckHealth at: %s with host: %s", t.String(), _h)
			h := _h
			wg.Add(1)
			go func() {
				defer wg.Done()
				settings := make(map[string]interface{})
				settings["hostname"] = h
				settings["timeout"] = float64(2)
				settings["product"] = "TEST"
				hchk, err := checks.NewFunctionPing(settings)
				if err != nil {
					log.Error(3, "Error creating healthcheck host: %s failed with err: %s", h, err.Error())
					hcheckrets <- 1
					return
				}
				_pingret, err := hchk.Run()
				if err != nil {
					log.Error(3, "Error while health checking with host: %s with err: %s with nil result",
						h, err.Error())
					hcheckrets <- 1
					return
				} else {
					pingret := _pingret.(*checks.PingResult)
					if pingret.Error != nil {
						log.Error(3, "Error while healchecking with host: %s with err: %s not nil result",
							h, pingret.Error)
						hcheckrets <- 1
						return
					}
				}
				hcheckrets <- 0
				return
			}()
		}
		wg.Wait()
		close(hcheckrets)

		//Checking result for health
		newstate := 0
		failedcheck := 0
		for hchk := range hcheckrets {
			failedcheck += hchk
		}
		if float64(failedcheck) > float64(len(s.HealthHosts))/2 {
			newstate = 1
			log.Error(3, "Host unhealthy with %d failedcheck / %d totalcheck", failedcheck, len(s.HealthHosts))
		} else {
			log.Info("Host healthy with %d failedcheck / %d totalcheck", failedcheck, len(s.HealthHosts))
		}

		if newstate != laststate {
			if newstate == 1 { //stop all check
				log.Info("Host unhealthy, stop all check")
				s.Lock()
				s.Healthy = false
				for _, chkInstance := range s.Check {
					_checkInstance := chkInstance
					go _checkInstance.Stop()
				}
				s.Unlock()
			} else { //restart check
				log.Info("Host healthy, start all check")
				s.Lock()
				s.Healthy = true
				for _, chkInstance := range s.Check {
					_checkInstance := chkInstance
					log.Debug("Start check: %s for %s", _checkInstance.Check.Type, _checkInstance.Check.Settings["hostname"])
					go _checkInstance.Run()
				}
				s.Unlock()
			}
		}
		laststate = newstate
	}
}
