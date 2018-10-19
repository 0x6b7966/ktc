package collector

import (
	"bufio"
	"os/exec"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

const (
	script = "./tcpretrans"
) 


var (
	scanner *bufio.Scanner
	ready = make(chan bool)
	info = make(chan string, 40960)
)

type tcpretransCollector struct {
	retrans typedDesc 
}

func init() {
	runTCPRetransScript()
	parseTCPRetransInfo()
	registerCollector("tcpretrans", defaultEnabled, NewTCPRetransCollector)
}

func runTCPRetransScript() {
	go func() {
		log.Infoln("Script: ", script)
		cmd := exec.Command(script)
		cmdReader, _ := cmd.StdoutPipe()
		scanner = bufio.NewScanner(cmdReader)
		cmd.Start()
		ready <- true
		cmd.Wait()
	}()
}

func parseTCPRetransInfo() {
	go func() {
		re_inside_whtsp := regexp.MustCompile(`[\s\p{Zs}]{2,}`)
		validID := regexp.MustCompile(`^[0-9]+$`)
		waitPipeReady()
		for scanner.Scan() {
			line := strings.SplitN(
				re_inside_whtsp.ReplaceAllString(scanner.Text(), " "), " ", 3)
			pid := line[1]
			if validID.MatchString(pid) && pid != "0" {
				info <- pid
			}
		}
	}()
}

func waitPipeReady() {
	<- ready
}

func getTCPRetransInfo() map[string]int {
	items := make(map[string]int)
	for {
		select {
			case i := <- info:
				items[i] += 1
			default:
				goto end
		}
	}
end:
	return items
}

func NewTCPRetransCollector() (Collector, error) {
	return &tcpretransCollector{
		retrans: typedDesc{prometheus.NewDesc(
                        prometheus.BuildFQName(namespace, "tcp", "retrans"),
                        "Tcp retrans info.",
                        []string{"pid"}, nil,
                ), prometheus.GaugeValue},
	}, nil
}

func (c *tcpretransCollector) Update(ch chan <- prometheus.Metric) error {
	items := getTCPRetransInfo()
	for k, v := range items {
		ch <- c.retrans.mustNewConstMetric(float64(v), k)
		log.Infoln("k: ", v, " v: ", k)
	}
	return nil
}
