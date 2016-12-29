package checks

import (
	"time"

	m "github.com/raintank/worldping-api/pkg/models"
	"gopkg.in/raintank/schema.v1"
)

const Limit = 1024 * 1024

type CheckResult interface {
	Metrics(time.Time, *m.CheckWithSlug) []*schema.MetricData
	ErrorMsg() string
}
