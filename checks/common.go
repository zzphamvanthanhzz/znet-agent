package checks

import (
	"time"

	m "github.com/raintank/worldping-api/pkg/models"
	"gopkg.in/raintank/schema.v1"
)

const Limit = 1024 * 1024
const RedirectLimit = 4
const NumFileLimit = 5
const CDNLastBytesSize = 2 * 1024 * 1024 //Bytes
const CDNUserName = "g2static.api"
const CDNPassword = "uD61BMZRofhPUdeWV0LJ"

type CheckResult interface {
	Metrics(time.Time, *m.CheckWithSlug) []*schema.MetricData
	ErrorMsg() string
}
