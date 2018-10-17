package collector

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
        _ "github.com/prometheus/common/log"
        _ "gopkg.in/alecthomas/kingpin.v2"
)

type tcpretransCollector struct {
	
}


func init() {
	registerCollector("tcpretrans", defaultEnabled, NewTCPRetransCollector)	
}

func NewTCPRetransCollector() (Collector, error) {
	fmt.Println("In NewTCPRetransCollector")	
	return &tcpretransCollector{}, nil
}

func (c *tcpretransCollector) Update(ch chan <- prometheus.Metric) error {
	fmt.Println("tcpretransCollector.Update be called")	
	ch <- nil	
	return nil
}
