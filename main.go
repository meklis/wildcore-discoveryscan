package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"net"
	"os"
	"snmpwalk/snmp"
	"strings"
	"time"
)

type cfg struct {
	Version     string
	Community   string
	Timeout     int
	Repeats     int
	Concurrency int
	Verbose     bool
}

var Cfg cfg

func init() {
}

func main() {
	app()
}

func app() {

	app := &cli.App{
		Name:      "snmpt",
		Usage:     "Tool for Autodiscovery component, of wildcoreDMS, for scan network",
		UsageText: "./discoveryscan snmp [command options] [arguments...]",
		ArgsUsage: "",
		Version:   "0.0.1",
		Commands: []*cli.Command{
			scanCommand(),
		},
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:        "concurrency",
				Usage:       "Num of concurrency scan",
				Value:       100,
				Destination: &Cfg.Concurrency,
			},
			&cli.BoolFlag{
				Name:        "verbose",
				Usage:       "Verbose output, with print errors (Errors prints with #)",
				Value:       false,
				Destination: &Cfg.Verbose,
			},
		},
		BashComplete: nil,
		Before:       nil,
		After:        nil,
		Action:       nil,
		CommandNotFound: func(c *cli.Context, command string) {
			fmt.Fprintf(c.App.Writer, "Command %q not found.\nType ./discoveryscan --help for list all supported commands\n", command)
		},
		OnUsageError:           nil,
		Compiled:               time.Time{},
		Copyright:              "Wildcore 2022",
		CustomAppHelpTemplate:  "",
		UseShortOptionHandling: false,
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf(`%v
`, err.Error())
		os.Exit(1)
	}
}

func scanCommand() *cli.Command {
	return &cli.Command{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "snmpversion",
				Usage:       "Snmp version. Variants: v1, v2c",
				Value:       "2c",
				Destination: &Cfg.Version,
				Aliases:     []string{"sv"},
			},
			&cli.StringFlag{
				Name:        "community",
				Usage:       "Community",
				Value:       "public",
				Destination: &Cfg.Community,
				Aliases:     []string{"c"},
			},
			&cli.IntFlag{
				Name:        "timeout",
				Value:       1,
				Usage:       "Timeout of snmp request",
				Destination: &Cfg.Timeout,
				Aliases:     []string{"t"},
			},
			&cli.IntFlag{
				Name:        "repeats",
				Value:       2,
				Usage:       "Timeout of snmp repeats",
				Destination: &Cfg.Repeats,
				Aliases:     []string{"r"},
			},
		},
		Name:        "snmp",
		Usage:       "snmp",
		Description: "scan networks over snmp",
		HelpName:    "snmp",
		Action: func(c *cli.Context) error {
			CIDR := c.Args().Get(0)
			ips, err := getIpsByCIDR(CIDR)
			if err != nil {
				log.Fatalf("err parse cidr: %v", err.Error())
			}
			startScan(ips)
			return nil
		},
	}
}

func getSNMP(ip string) (error, *snmp.Snmp) {
	var vers snmp.SnmpVersion
	switch Cfg.Version {
	case "1":
		vers = snmp.Version1
		break
	case "2c":
		vers = snmp.Version2c
		break
	}
	return snmp.Connect(snmp.InitStruct{
		Version:    vers,
		TimeoutSec: time.Duration(Cfg.Timeout) * time.Second,
		Repeats:    Cfg.Repeats,
		Ip:         ip,
		Community:  Cfg.Community,
	})
}

//dont do this, see above edit
func prettyprint(b []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}

func getIpsByCIDR(cidr string) ([]string, error) {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	ips := make([]string, 0)
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func startScan(ips []string) {
	stopSignal := make(chan interface{})
	ipPool := make(chan string, 10)
	processed := make(chan string, 50)

	//Send IPs
	go func() {
		for _, ip := range ips {
			ipPool <- ip
		}
	}()

	//Scan gorutines
	for i := 0; i < Cfg.Concurrency; i++ {
		go func() {
			for {
				select {
				case ip := <-ipPool:
					err, SNMP := getSNMP(ip)
					if err != nil {
						if Cfg.Verbose {
							processed <- fmt.Sprintf("#%v;%v", ip, err.Error())
						} else {
							processed <- ""
						}
						continue
					}
					err, response := SNMP.Get(".1.3.6.1.2.1.1.1.0")
					if err != nil {
						if Cfg.Verbose {
							processed <- fmt.Sprintf("#%v;%v", ip, err.Error())
						} else {
							processed <- ""
						}
						continue
					}
					var respLastValue interface{}
					for _, resp := range response {
						respLastValue = resp.Value
					}
					processed <- fmt.Sprintf("%v;%v", ip, respLastValue)
				case <-stopSignal:
					return
				}
			}
		}()
	}

	countReceivedFinished := 0
	for {
		select {
		case resp := <-processed:
			countReceivedFinished++
			resp = strings.Replace(resp, "\n", " ", -1)
			resp = strings.Replace(resp, "\r", "", -1)
			if resp != "" {
				fmt.Println(resp)
			}
			if countReceivedFinished >= len(ips) {
				for i := 0; i < Cfg.Concurrency; i++ {
					stopSignal <- true
				}
				time.Sleep(time.Millisecond)
				return
			}
		default:
			time.Sleep(time.Millisecond * 500)
		}
	}
}
