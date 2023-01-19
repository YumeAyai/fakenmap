package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	var host string
	var segment string
	flag.StringVar(&host, "s", "", "the host of ports you scan, as '127.0.0.1'")
	flag.StringVar(&segment, "n", "", "network segment you scan, as '192.168.0.0/24'")
	flag.Parse()
	if host != "" {
		postscan(host)
	} else if segment != "" {
		hostseg(segment)
	} else {
		fmt.Println("Check out your input")
	}
}

func postscan(host string) {
	var wg sync.WaitGroup
	ports := make(chan int, 50)
	for i := 1; i <= 50000; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Second)
			if err != nil {
				// log.Printf("Error:%v.Port:[%d]\n", err, port)
			} else {
				conn.Close()
				log.Printf("Connection successful.Port:[%d]\n", port)
				ports <- port
			}
		}(i)
	}
	wg.Wait()
	fmt.Print("Opened ports:")
	for {
		select {
		case i := <-ports:
			fmt.Print(i, ",")
		case <-time.After(time.Second * 1):
			fmt.Println("over")
			return
		}
	}
}

func hostseg(segment string) {
	hosts := cidr(segment)
	tasksChan := make(chan string, len(hosts))
	resChan := make(chan string, len(hosts))
	exitChan := make(chan bool, 50)
	var wg sync.WaitGroup
	for _, host := range hosts {
		tasksChan <- host
	}
	close(tasksChan)
	start := time.Now()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go ScanHostTasks(tasksChan, resChan, exitChan, &wg)
	}
	wg.Wait()
	for i := 0; i < 4; i++ {
		<-exitChan
	}
	close(resChan)
	end := time.Since(start)
	for {
		openhost, ok := <-resChan
		if !ok {
			break
		}
		fmt.Println("Active Host ", openhost)
	}
	fmt.Println("Time spend", end)
}

// icmp发现主机
func hostscan(ip string, count int) bool {
	var cmd = &exec.Cmd{}
	//判断当前系统是什么系统，不同的系统ping的使用稍有不同
	switch runtime.GOOS {
	case "windows":
		//go中使用exec.Command执行系统命令，每一个参数都各占一个位置
		cmd = exec.Command("ping", "-n", strconv.Itoa(count), ip)
	default:
		cmd = exec.Command("ping", "-c", strconv.Itoa(count), ip)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	defer output.Close()
	cmd.Start()
	if err != nil {
		log.Fatal(err)
	} else {
		result, err := ioutil.ReadAll(output)
		if err != nil {
			log.Fatal(err)
		}
		//通过返回的内容中是否存在TTL字段来判断主机是否在线
		if strings.Contains(string(result), "TTL") || strings.Contains(string(result), "ttl") {
			return true
		} else {
			return false
		}
	}
	return false
}

// hostsChan存放要扫描的主机，resChan存放扫描的结果，exitChan存储每一个goroutine完成的状态，wg用来同步各个goroutiine
func ScanHostTasks(hostsChan chan string, resChan chan string, exitChan chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		host, ok := <-hostsChan
		if !ok {
			break
		} else {
			res := hostscan(host, 4)
			if res {
				resChan <- host
			}
		}
	}
	exitChan <- true
}

func cidr(segment string) []string {
	var hosts []string
	tmp := strings.Split(segment, "/")[1]
	s, err := strconv.Atoi(tmp)
	if err != nil {
		fmt.Print("error")
	}
	if s > 16 && s <= 24 {
		hosts = getCidrIpRange(segment)
	} else if s > 24 && s < 32 {
		hosts = getCidrIpRange(segment)
	}
	return hosts
}

func getCidrIpRange(cidr string) []string {
	var hosts []string
	var host string
	var seg3Ip, seg4Ip int
	ip := strings.Split(cidr, "/")[0]
	ipSegs := strings.Split(ip, ".")
	maskLen, _ := strconv.Atoi(strings.Split(cidr, "/")[1])
	seg3MinIp, seg3MaxIp := getIpSeg3Range(ipSegs, maskLen)
	seg4MinIp, seg4MaxIp := getIpSeg4Range(ipSegs, maskLen)
	ipPrefix := ipSegs[0] + "." + ipSegs[1] + "."
	if seg3MinIp == seg3MaxIp {
		seg3Ip = seg3MaxIp
		if seg4MinIp > seg4MaxIp {
			fmt.Printf("error")
		}
		for seg4Ip = 1; seg4Ip < seg4MaxIp; seg4Ip++ {
			host = string(ipPrefix + strconv.Itoa(seg3Ip) + "." + strconv.Itoa(seg4Ip))
			hosts = append(hosts, host)
		}
	} else {
		for seg3Ip = 0; seg3Ip < seg3MaxIp; seg3Ip++ {
			for seg4Ip = 1; seg4Ip < 255; seg4Ip++ {
				host = string(ipPrefix + strconv.Itoa(seg3Ip) + "." + strconv.Itoa(seg4Ip))
				hosts = append(hosts, host)
			}
		}

	}
	return hosts
}

func getIpSeg3Range(ipSegs []string, maskLen int) (int, int) {
	if maskLen > 24 {
		segIp, _ := strconv.Atoi(ipSegs[2])
		return segIp, segIp
	}
	ipSeg, _ := strconv.Atoi(ipSegs[2])
	return getIpSegRange(uint8(ipSeg), uint8(24-maskLen))
}

func getIpSeg4Range(ipSegs []string, maskLen int) (int, int) {
	ipSeg, _ := strconv.Atoi(ipSegs[3])
	segMinIp, segMaxIp := getIpSegRange(uint8(ipSeg), uint8(32-maskLen))
	return segMinIp + 1, segMaxIp
}

func getIpSegRange(userSegIp, offset uint8) (int, int) {
	var ipSegMax uint8 = 255
	netSegIp := ipSegMax << offset
	segMinIp := netSegIp & userSegIp
	segMaxIp := userSegIp&(255<<offset) | ^(255 << offset)
	return int(segMinIp), int(segMaxIp)
}
