package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/graarh/golang-socketio"
	"github.com/graarh/golang-socketio/transport"
	"github.com/raintank/worldping-api/pkg/log"
	m "github.com/raintank/worldping-api/pkg/models"
	"github.com/rakyll/globalconf"
	"github.com/zzphamvanthanhzz/znet-agent/probe"
	"github.com/zzphamvanthanhzz/znet-agent/publisher"
	"github.com/zzphamvanthanhzz/znet-agent/scheduler"
)

const Version int = 1

var (
	showVersion      = flag.Bool("version", false, "show GOLANG version, then exist")
	logLevel         = flag.Int("log-level", 2, "log level: 0=TRACE|1=DEBUG|2=INFO|3=WARN|4=ERROR|5=CRITICAL|6=FATAL")
	confFile         = flag.String("config-file", "./agent.ini", "config path")
	serverAddr       = flag.String("server-api", "wss://localhost:81/", "world-ping api")
	tsdbAddr         = flag.String("tsdb-server", "http://localhost:82/", "tsdb addr")
	nodeName         = flag.String("name", "test2", "node name to distinguish")
	apiKey           = flag.String("api-key", "123456@A", "Api key for pushing data to world-ping api") //Key for WORLDPING-API, not TSDB-GW
	concurrency      = flag.Int("concurrency", 5, "number of concurrency requests to TSDB")
	publicChecksFile = flag.String("public-checks", "./publicChecks.json", "path to public check file")
	healthHosts      = flag.String("health-hosts", "facebook.com,google.com,news.zing.vn,twitter.com", "Host used for healthcheck")

	//Data Transfer Object
	MonitorTypes map[string]m.MonitorTypeDTO

	//
	PublicChecks []m.CheckWithSlug
)

func main_() {
	healStr := "facebook.com,google.com"
	hcheck := make([]string, 0)
	for _, c := range strings.Split(healStr, ",") {
		hcheck = append(hcheck, c)
	}
	fmt.Println(len(hcheck))
}
func main() {
	flag.Parse()

	var cfile string
	if _, err := os.Stat(*confFile); err == nil {
		cfile = *confFile
	}
	log.Info("Start Agent with config file: %s\n", cfile)

	conf, err := globalconf.NewWithOptions(&globalconf.Options{
		Filename:  cfile,
		EnvPrefix: "AGENT_",
	})

	if err != nil {
		panic(fmt.Sprintf("Error config file: %s", cfile))
	}
	conf.ParseAll()

	log.NewLogger(0, "console", fmt.Sprintf(`{"level": %d, "formatting":true}`, *logLevel))
	switch *logLevel {
	case 0:
		log.Level(log.TRACE)
	case 1:
		log.Level(log.DEBUG)
	case 2:
		log.Level(log.INFO)
	case 3:
		log.Level(log.WARN)
	case 4:
		log.Level(log.ERROR)
	case 5:
		log.Level(log.CRITICAL)
	case 6:
		log.Level(log.FATAL)
	default:
		log.Level(log.FATAL)
	}

	if *showVersion {
		fmt.Sprintf("Running with Agent version: %s\n", runtime.Version())
	}

	if *nodeName == "" {
		log.Fatal(4, "Node name must be set")
	}

	file, err := ioutil.ReadFile(*publicChecksFile)
	if err != nil {
		log.Error(3, "Could not read publicChecks file. %s", err.Error())
	} else {
		err = json.Unmarshal(file, &PublicChecks)
		if err != nil {
			log.Error(3, "Could not parse publicChecks file. %s", err.Error())
			return
		}
	}
	log.Info("Start Agent with public check file: %s", *publicChecksFile)
	log.Info("Start Agent with health hosts: %s", *healthHosts)
	for index, publicCheck := range PublicChecks {
		log.Info("Start Agent with public checks: %d of type: %s of Id: %d, OrgId: %d, EndpointId: %d of Host: %s",
			index, publicCheck.Type, publicCheck.Id, publicCheck.OrgId, publicCheck.EndpointId, publicCheck.Settings["hostname"])
	}

	jobScheduler := scheduler.New(*healthHosts)
	go jobScheduler.CheckHealth()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	//
	controllerUrl, err := url.Parse(*serverAddr)
	if err != nil {
		log.Fatal(4, err.Error())
	}
	version := "1.0.0"

	rawUrl := gosocketio.GetUrl("api.qos.zapps.vn", 3000, false)
	controllerUrl.Path = path.Clean(controllerUrl.Path + "/socket.io")
	controllerUrl.RawQuery = fmt.Sprintf("EIO=3&transport=websocket&apiKey=%s&name=%s&version=%s", *apiKey, url.QueryEscape(*nodeName), version)
	fmt.Println(controllerUrl.String())
	client, err := gosocketio.Dial(controllerUrl.String(), transport.GetDefaultWebsocketTransport())
	if err != nil {
		log.Fatal(4, "Error binding socket to api server: %s with err: %s ", rawUrl, err.Error())
	}
	log.Debug("Connect successfully to api server: %s", rawUrl)
	//tsdb for event and metrics
	tsdbUrl, err := url.Parse(*tsdbAddr)
	if err != nil {
		log.Fatal(4, "Invalid TSDB url.", err)
	}
	if !strings.HasPrefix(tsdbUrl.Path, "/") {
		tsdbUrl.Path += "/"
	}
	publisher.Init(tsdbUrl, *apiKey, *concurrency)

	bindHandlers(client, controllerUrl, jobScheduler, interrupt)

	<-interrupt
	log.Info("Interrrupt")
	jobScheduler.Close()
	client.Close()
}

func bindHandlers(client *gosocketio.Client, controllerUrl *url.URL,
	jobScheduler *scheduler.Scheduler, interrupt chan os.Signal) {

	client.On(gosocketio.OnDisconnection, func(c *gosocketio.Channel) {
		log.Error(4, "Disconnect from server: %s", controllerUrl.String())
		connected := false
		for !connected {
			client, err := gosocketio.Dial(controllerUrl.String(), transport.GetDefaultWebsocketTransport())
			if err != nil {
				log.Error(4, err.Error())
				time.Sleep(time.Duration(30) * time.Second)
			} else {
				connected = true
				bindHandlers(client, controllerUrl, jobScheduler, interrupt)
			}
		}
	})

	client.On("refresh", func(c *gosocketio.Channel, checks []*m.CheckWithSlug) {
		for _, c := range PublicChecks {
			_c := c
			checks = append(checks, &_c)
		}
		jobScheduler.Refresh(checks)
	})

	client.On("created", func(c *gosocketio.Channel, check m.CheckWithSlug) {
		jobScheduler.Create(&check)
	})

	client.On("updated", func(c *gosocketio.Channel, check m.CheckWithSlug) {
		jobScheduler.Update(&check)
	})

	client.On("removed", func(c *gosocketio.Channel, check m.CheckWithSlug) {
		jobScheduler.Remove(&check)
	})

	client.On("ready", func(c *gosocketio.Channel, event m.ProbeReadyPayload) {
		log.Info("server sent ready event. ProbeId=%d", event.Collector.Id)
		probe.Self = event.Collector

		queryParams := controllerUrl.Query()
		queryParams["lastSocketId"] = []string{event.SocketId}
		controllerUrl.RawQuery = queryParams.Encode()

	})

	client.On("error", func(c *gosocketio.Channel, reason string) {
		log.Error(3, "Controller emitted an error. %s", reason)
		close(interrupt)
	})
}