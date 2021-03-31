package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    "github.com/apoorvam/goterminal"
    "github.com/axgle/mahonia"
    "github.com/saintfish/chardet"
    //"github.com/apoorvam/goterminal"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"
)

var formatString = "%s:%d [%s] [%d %s] [%s] [%s]"

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
    failover bool
    transportLayerScan bool
    redirectOutput bool
    logFilename string
}

type Result struct {
    task Task
    responseData []byte
    status int
    banner string
    err error
}

type Task interface {
    scan() ([]byte, int, string, error)
    getHost() string
    getService() ServicePort
    getProtoName() string
    needReschedule() bool
    schedule()
}

type HttpScanTask struct {
    host string
    service ServicePort
    proxy *url.URL
    timeout int
    scheduled bool
}

type TransportLayerScanTask struct {
    host string
    service ServicePort
    timeout int
}

func (task *TransportLayerScanTask) scan() ([]byte, int, string, error) {
    target := fmt.Sprintf("%s:%d", task.host, task.service.port)
    conn, err := net.DialTimeout(task.service.protocol, target, time.Duration(task.timeout) * time.Second)
    if err != nil {
        return nil, 0, "", err;
    }

    err = conn.Close()
    if err != nil {
        // Deal with unexpected connect closeds
    }

    return nil, 0, "", nil
}

func (task *TransportLayerScanTask) getHost() string {
    return task.host
}

func (task *TransportLayerScanTask) getService() ServicePort {
    return task.service
}

func (task *TransportLayerScanTask) needReschedule() bool {
    return false
}

func (task *TransportLayerScanTask) schedule() {
}

func (task *TransportLayerScanTask) getProtoName() string {
    return strings.ToUpper(task.service.protocol)
}

func (task *HttpScanTask) scan() ([]byte, int, string, error) {
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

    content, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, 0, "", err
    }

    err = resp.Body.Close()
    if err != nil {
        // unexpected connection closed, receive the error to avoid the function been broken
    }

    return content, resp.StatusCode, resp.Header.Get("Server"), err
}

func (task *HttpScanTask) getHost() string {
    return task.host
}

func (task *HttpScanTask) getService() ServicePort {
    return task.service
}

func (task *HttpScanTask) needReschedule() bool {
    return ! task.scheduled && ! task.service.ssl
}

func (task *HttpScanTask) schedule() {
    task.scheduled = true
    task.service.ssl = true
}

func (task *HttpScanTask) getProtoName() string {
    if task.service.ssl {
        return "HTTPS"
    } else {
        return "HTTP"
    }
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

func readTarget(filename string) []string {
    var targets []string

    file, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        targets = append(targets, strings.Trim(scanner.Text(), " \r\n"))
    }

    return targets
}

func present(result *Result) {
    var title string

    if len(result.responseData) > 0 {
        encoding := guessEncoding(result.responseData)
        decoder := mahonia.NewDecoder(encoding)
        content := decoder.ConvertString(string(result.responseData))
        title = extractTitle(content)
    }

    task := result.task
    log := fmt.Sprintf(formatString, task.getHost(), task.getService().port, task.getProtoName(),
        result.status, http.StatusText(result.status), result.banner, title)

    fmt.Println(log)
}

func worker(tasks chan Task, results chan *Result, options Option) {
    for task := range tasks {
    scan:
        // fmt.Printf("host: %s, port: %d, ssl: %v\n", task.getHost(), task.getService().port, task.getService().ssl);
        responseData, status, banner, err := task.scan()
        if err != nil && options.failover && task.needReschedule() {
            // fmt.Printf("Reschedule task %s:%d...\n", task.getHost(), task.getService().port)
            // Re-schedule the task
            task.schedule()
            goto scan
        }

        results <- &Result{ task, responseData, status, banner, err }
    }
}

func startScan(hosts []string, services []ServicePort, options Option) {
    var lock sync.WaitGroup
    tasks := make(chan Task, options.threads)
    results := make(chan *Result)

    for i := 0; i < options.threads; i++ {
        go worker(tasks, results, options)
    }

    lock.Add(1)
    go func() {
        var writer *goterminal.Writer
        // Calculating the number of tasks
        totalTask := len(hosts) * len(services)

        if ! options.redirectOutput && isPty() {
            writer = goterminal.New(os.Stdout)
            fmt.Fprintf(writer, "Scanning (0/%d) services...\n", totalTask)
            writer.Print()
        }

        for i := 1; i <= totalTask; i++ {
            result := <- results

            if writer != nil {
                writer.Clear()
            }

            if result.err == nil {
                present(result)
            }

            if writer != nil {
                fmt.Fprintf(writer, "Scanning (%d/%d) services...\n", i, totalTask)
                writer.Print()
            }
        }

        if writer != nil {
            writer.Clear()
            writer.Reset()
            fmt.Println("All done <3")
        }

        lock.Done()
    }()

    for _, host := range hosts {
        for _, service := range services {
            if options.transportLayerScan {
                tasks <- &TransportLayerScanTask { host, service, options.timeout }
            } else {
                tasks <- &HttpScanTask { host, service, options.proxyURL, options.timeout, false }
            }
        }
    }

    lock.Wait()

    close(tasks)
    close(results)
}

// This works on Unix* system only :(
func isPty() bool {
    file, err := os.Stdin.Stat()
    if err != nil {
        return false
    }

    return (file.Mode() & os.ModeCharDevice) != 0
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
            upper = port
        } else if strings.HasPrefix(port, "u") {
            protocol = "udp"
            port = port[1:]
            upper = port
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
    threads := flag.Int("threads", 20, "Maximum number of threads")
    timeout := flag.Int("timeout", 10, "Default timeout for connection session")
    proxy := flag.String("proxy", "", "Specify a proxy server for all connection, currently HTTP and SOCKS5 are supported, this work only on the HTTP mode")
    transportLayerScan := flag.Bool("tcp", false, "Switch the scanning mode to TCP/UDP instead of HTTP request")
    redirect := flag.String("o", "", "Redirect the output to local file")
    failover := flag.Bool("failover", false, "Fallback to HTTPS connection if the normal HTTP request was failed, this works on HTTP scan mode only")

    flag.Parse()

    return Option{ *ports, *filename, *threads, *timeout, *proxy, nil, *failover,
        *transportLayerScan, false, *redirect }, flag.Args()
}

func main() {
    var hosts []string
    options, targets := initArguments()

    if len(options.logFilename) > 0 {
        handle, err := os.OpenFile(options.logFilename, os.O_RDWR | os.O_CREATE, 0755)
        if err != nil {
            log.Fatal(err)
        }

        os.Stdout = handle
        options.redirectOutput = true
    }

    if options.filename != "" {
        read := readTarget(options.filename)
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

    for _, target := range targets {
        // Parsing the targets before launch the scanning in case there are CIDRs in target hosts
        for _, host := range parseTarget(target) {
            hosts = append(hosts, host)
        }
    }

    services := parsePort(options.ports)

    startScan(hosts, services, options)
}
