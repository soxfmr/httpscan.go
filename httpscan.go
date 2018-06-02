package main 

import (
    "os"
    "fmt"
    "net"
    "log"
    "sync"
    "time"
    "flag"
    "sort"
    "bufio"
    "regexp"
    "strconv"
    "strings"
    "net/url"
    "net/http"
    "crypto/tls"
    "io/ioutil"
    "unicode/utf8"
    mahonia "github.com/axgle/mahonia"
    chardet "github.com/saintfish/chardet"
)

var maxTitleAlign = 36
var maxBannerAlign = 26

var delimiter = "+----------------+------------+--------+--------------------------+------------------------------------+"
var formatString = "|%-16s|%-12s|%-8s|%-*s|%-*s|"
var logHeader = fmt.Sprintf(formatString, "Host", "Port", "Status", maxBannerAlign, "Banner", maxTitleAlign, "Title")

type ServicePort struct {
    ssl bool
    port int
    protocol string
}

type Option struct {
    ports string
    filename string
    threads int
    timeout int
    proxy string
    proxyURL *url.URL
    transportLayerScan bool
    redirect string
}

type Task interface {
    scan() ([]byte, int, string, error)
    getHost() string
    getService() ServicePort
}

type HttpScanTask struct {
    host string
    service ServicePort
    proxy *url.URL
    timeout int
}

type TransportLayerScanTask struct {
    host string
    service ServicePort
    timeout int
}

func (task TransportLayerScanTask) scan() ([]byte, int, string, error) {
    target := fmt.Sprintf("%s:%d", task.host, task.service.port)
    conn, err := net.DialTimeout(task.service.protocol, target, time.Duration(task.timeout) * time.Second)
    if err != nil {
        return nil, 0, "", err;
    }

    conn.Close()

    return nil, 0, "", nil
}

func (task TransportLayerScanTask) getHost() (string) {
    return task.host
}

func (task TransportLayerScanTask) getService() ServicePort {
    return task.service
}

func (task HttpScanTask) scan() ([]byte, int, string, error) {
    var schema string
    if task.service.ssl {
        schema = "https://"
    } else {
        schema = "http://"
    }

    url := schema + task.host + ":" + strconv.Itoa(task.service.port)

    transport := &http.Transport {
        Proxy: http.ProxyURL(task.proxy),
        DialContext: (&net.Dialer{
            Timeout: time.Duration(task.timeout) * time.Second,
        }).DialContext,
        TLSClientConfig: &tls.Config {
            InsecureSkipVerify: true,
        },
    }

    client := &http.Client{ 
        Transport: transport,
    }

    resp, err := client.Get(url)
    if err != nil {
        return nil, 0, "", err
    }
    defer resp.Body.Close()

    content, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, 0, "", err
    }

    return content, resp.StatusCode, resp.Header.Get("Server"), err
}

func (task HttpScanTask) getHost() (string) {
    return task.host
}

func (task HttpScanTask) getService() ServicePort {
    return task.service
}

func guessEncoding(bytes []byte) string {
    detector := chardet.NewHtmlDetector()
    result, err := detector.DetectBest(bytes)
    if err != nil || result.Confidence < 60 {
        return "utf-8"
    }

    return result.Charset
}

func extractTitle(content string) string {
    pattern := regexp.MustCompile("(?is)<title>(.+?)</title>")
    strip := regexp.MustCompile("(?s)[\t\n\r]+")

    match := pattern.FindStringSubmatch(content)
    if match == nil {
        return ""
    }

    return strings.Trim(strip.ReplaceAllString(match[1], ""), " ")
}

func readTraget(filename string) []string {
    var targets []string

    file, err := os.Open(filename)
    if err != nil {
        return nil
    }
    defer file.Close()

    reader := bufio.NewReader(file)
    for {
        line, err := reader.ReadString('\n')
        if err != nil {
            break
        }

        targets = append(targets, strings.Trim(line, " \r\n"))
    }

    return targets
}

func isASCII(char string) bool {
    return string(char[0]) == char && len(char) < 2
}

func shrinkText(text string, max int) string {
    var align int
    var result string

    for _, char := range strings.Split(text, "") {
        if isASCII(char) {
            align++
        } else {
            align += 2
        }

        if align > max {
            break
        }

        result += string(char)
    }

    return result
}

func calcAlign(text string, max int) int {
    // Multi-bytes string length
    mbsLen := len(text)
    realLen := utf8.RuneCountInString(text)

    // All of ASCII char, we'r safe :)
    if mbsLen == 0 || mbsLen == realLen {
        return max
    }

    // How many Unicode characters in string
    mbsNum := 0
    slices := strings.Split(text, "")
    for _, slice := range slices {
        if ! isASCII(slice) {
            mbsNum++
        }
    }

    return max - mbsNum
}

func prologue() {
    fmt.Println(delimiter)
    fmt.Println(logHeader)
    fmt.Println(delimiter)
}

func present(host string, service ServicePort, result []byte, status int, banner string) {
    var title string
    port := strconv.Itoa(service.port)

    if service.ssl {
        port = port + " (SSL)"
    } else if service.protocol == "UDP" {
        port = port + " (UDP)"
    }

    if len(banner) > 0 {
        encoding := guessEncoding(result)

        decoder := mahonia.NewDecoder(encoding)
        content := decoder.ConvertString(string(result))
    
        banner = shrinkText(banner, maxBannerAlign)
        title = shrinkText(extractTitle(content), maxTitleAlign)
    }

    log := fmt.Sprintf(formatString, host, port, strconv.Itoa(status), 
        calcAlign(banner, maxBannerAlign), banner, calcAlign(title, maxTitleAlign), title)
    
    // fmt.Println(delimiter)
    fmt.Println(log)
    fmt.Println(delimiter)
}

func worker(tasks <-chan Task, options Option, lock *sync.WaitGroup) {
    for task := range tasks {
        result, status, banner, err := task.scan()
        if err == nil {
            present(task.getHost(), task.getService(), result, status, banner)
        }
        lock.Done()
    }
}

func startScan(targets []string, services []ServicePort, options Option) {
    var lock sync.WaitGroup
    tasks := make(chan Task, options.threads)

    for i := 0; i < options.threads; i++ {
        go worker(tasks, options, &lock)
    }

    prologue()

    for _, target := range targets {
        // parse the traget and send to queue
        for _, host := range parseTarget(target) {
            for _, service := range services {
                if options.transportLayerScan {
                    tasks <- TransportLayerScanTask { host, service, options.timeout }
                } else {
                    tasks <- HttpScanTask { host, service, options.proxyURL, options.timeout }
                }
                lock.Add(1)
            }
        }
    }
    close(tasks)

    lock.Wait()
}

func nextAddr(address []byte) {
    for i := len(address) - 1; i >= 0; i-- {
        address[i]++
        if address[i] > 0 {
            break
        }
    }
}

func isReserveAddr(address []byte) bool {
    return address[3] == 0 || address[3] == 0xff
}

func parseTarget(target string) []string {
    var result []string
    pattern := regexp.MustCompile(`([0-9]+\.){3}[0-9]+/[0-9]{1,2}`)
    if pattern.MatchString(target) {
        ip, net, _ := net.ParseCIDR(target)
        for address := ip.Mask(net.Mask); net.Contains(address); nextAddr(address) {
            if isReserveAddr(address) {
                continue
            }
            result = append(result, address.String())
        }
    } else {
        result = append(result, target)
    }

    return result
}

/**
* Shit code here to parse the humanable port list
*/
func parsePort(ports string) []ServicePort {
    var services []ServicePort
    slices := strings.Split(ports, ",")

    for _, port := range slices {
        port = strings.Trim(port, " ")
        ssl := false
        upper := port
        protocol := "tcp"
        
        // 8001-8009
        if strings.Contains(port, "-") {
            ranges := strings.Split(port, "-")

            if len(ranges) < 2 {
                continue
            }
            
            sort.Strings(ranges)
            port = ranges[0]
            upper = ranges[1]
        } else if strings.HasPrefix(port, "s") {
            ssl = true
            port = port[1:]
        } else if strings.HasPrefix(port, "u") {
            protocol = "udp"
            upper = port[1:]
        }
        
        start, _ := strconv.Atoi(port)
        end, _ := strconv.Atoi(upper)

        for i := start; i <= end; i++ {
            service := ServicePort{ ssl, i, protocol }
            services = append(services, service)
        }
    }
    return services
}

func initArguments() (Option, []string) {
    ports := flag.String("port", "80", "List of port(s) to be scan, such as 80,8000-8009,s443 etc. Port starts with 's' prefix indicate that the connection will be negotiate with SSL/TLS. Similar starts with 'u' for UDP connection")
    filename := flag.String("file", "", "Specify a local file contains a list of URLs")
    threads := flag.Int("threads", 20, "Maxinum number of threads")
    timeout := flag.Int("timeout", 10, "Default timeout for connection session")
    proxy := flag.String("proxy", "", "Specify a proxy server for all connection, currently HTTP and SOCKS5 are supported, this work only on the HTTP mode")
    transportLayerScan := flag.Bool("tcp", false, "Switch the scanning mode to TCP/UDP instead of HTTP request")
    redirect := flag.String("o", "", "Redirect the output to local file")

    flag.Parse()

    return Option{ *ports, *filename, *threads, *timeout, *proxy, nil, *transportLayerScan, *redirect }, flag.Args()
}

func main() {
    options, targets := initArguments()

    if len(options.redirect) > 0 {
        handle, err := os.OpenFile(options.redirect, os.O_RDWR | os.O_CREATE, 0755)
        if err != nil {
            log.Fatal(err)
        }
        
        os.Stdout = handle
    }

    if options.filename != "" {
        read := readTraget(options.filename)
        targets = append(targets, read...)
    }

    if options.proxy != "" {
        proxyURL, err := url.Parse(options.proxy)
        if err != nil {
            log.Fatal("Invalid proxy address " + options.proxy)
        }
        options.proxyURL = proxyURL
    }

    if len(targets) == 0 {
        log.Fatal("No targets specified")
    }
    
    services := parsePort(options.ports)

    startScan(targets, services, options)
}
