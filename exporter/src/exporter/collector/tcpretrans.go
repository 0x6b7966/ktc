package collector

import (
	"bufio"
	"os/exec"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
        _ "github.com/prometheus/common/log"
        _ "gopkg.in/alecthomas/kingpin.v2"
)

const (
	script = "./tcpretrans"
)

var (
	scanner *bufio.Scanner
	ready = make(chan bool)
	info = make(chan string, 4096)
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
		waitPipeReady()
		if scanner.Scan() {
			scanner.Text()
		}
		for scanner.Scan() {
			line := strings.SplitN(
				re_inside_whtsp.ReplaceAllString(scanner.Text(), " "), " ", 4)
			info <- line[len(line) - 1]
		}
	}()
}

func waitPipeReady() {
	<- ready
}

func getTCPRetransInfo() []string {
	items := []string{}
	for {
		select {
			case i := <- info:
				items = append(items, i)
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
                        []string{"tcp"}, nil,
                ), prometheus.GaugeValue},
	}, nil
}

func (c *tcpretransCollector) Update(ch chan <- prometheus.Metric) error {
	items := getTCPRetransInfo()
	for _, item := range items {
		ch <- c.retrans.mustNewConstMetric(1, item)
	}
	return nil
}
