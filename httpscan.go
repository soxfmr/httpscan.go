package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    "github.com/apoorvam/goterminal"
    "github.com/axgle/mahonia"
    "github.com/saintfish/chardet"
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
    SSL bool
    Port int
    Protocol string
}

type Option struct {
    Ports string
    Filename string
    Threads int
    Timeout int
    Proxy string
    ProxyURL *url.URL
    Failover bool
    TransportLayerScan bool
    RedirectOutput bool
    LogFilename string
}

type Result struct {
    Task Task
    ResponseData []byte
    Status int
    Banner string
    Error error
}

type Task interface {
    Scan() ([]byte, int, string, error)
    GetHost() string
    GetService() ServicePort
    GetProtoName() string
    NeedReschedule() bool
    Schedule()
}

type HttpScanTask struct {
    Host string
    Service ServicePort
    Proxy *url.URL
    Timeout int
    Scheduled bool
}

type TransportLayerScanTask struct {
    Host string
    Service ServicePort
    Timeout int
}

func (task *TransportLayerScanTask) Scan() ([]byte, int, string, error) {
    target := fmt.Sprintf("%s:%d", task.Host, task.Service.Port)
    conn, err := net.DialTimeout(task.Service.Protocol, target, time.Duration(task.Timeout) * time.Second)
    if err != nil {
        return nil, 0, "", err
    }

    err = conn.Close()
    if err != nil {
        // Deal with problem when connection was closed unexpected
    }

    return nil, 0, "", nil
}

func (task *TransportLayerScanTask) GetHost() string {
    return task.Host
}

func (task *TransportLayerScanTask) GetService() ServicePort {
    return task.Service
}

func (task *TransportLayerScanTask) NeedReschedule() bool {
    return false
}

func (task *TransportLayerScanTask) Schedule() {
}

func (task *TransportLayerScanTask) GetProtoName() string {
    return strings.ToUpper(task.Service.Protocol)
}

func (task *HttpScanTask) Scan() ([]byte, int, string, error) {
    var schema string
    if task.Service.SSL {
        schema = "https://"
    } else {
        schema = "http://"
    }

    uri := schema + task.Host + ":" + strconv.Itoa(task.Service.Port)

    transport := &http.Transport {
        Proxy: http.ProxyURL(task.Proxy),
        DialContext: (&net.Dialer{
            Timeout: time.Duration(task.Timeout) * time.Second,
        }).DialContext,
        TLSClientConfig: &tls.Config {
            InsecureSkipVerify: true,
        },
    }

    client := &http.Client{
        Transport: transport,
    }

    resp, err := client.Get(uri)
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

func (task *HttpScanTask) GetHost() string {
    return task.Host
}

func (task *HttpScanTask) GetService() ServicePort {
    return task.Service
}

func (task *HttpScanTask) NeedReschedule() bool {
    return ! task.Scheduled && ! task.Service.SSL
}

func (task *HttpScanTask) Schedule() {
    task.Scheduled = true
    task.Service.SSL = true
}

func (task *HttpScanTask) GetProtoName() string {
    if task.Service.SSL {
        return "HTTPS"
    } else {
        return "HTTP"
    }
}

func GuessEncoding(bytes []byte) string {
    detector := chardet.NewHtmlDetector()
    result, err := detector.DetectBest(bytes)
    if err != nil || result.Confidence < 60 {
        return "utf-8"
    }

    return result.Charset
}

func ExtractTitle(content string) string {
    pattern := regexp.MustCompile("(?is)<title>(.+?)</title>")
    strip := regexp.MustCompile("(?s)[\t\n\r]+")

    match := pattern.FindStringSubmatch(content)
    if match == nil {
        return ""
    }

    return strings.Trim(strip.ReplaceAllString(match[1], ""), " ")
}

func ReadTarget(filename string) []string {
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

func Present(result *Result) {
    var title string

    if len(result.ResponseData) > 0 {
        encoding := GuessEncoding(result.ResponseData)
        decoder := mahonia.NewDecoder(encoding)
        content := decoder.ConvertString(string(result.ResponseData))
        title = ExtractTitle(content)
    }

    task := result.Task
    output := fmt.Sprintf(formatString, task.GetHost(), task.GetService().Port, task.GetProtoName(),
        result.Status, http.StatusText(result.Status), result.Banner, title)

    fmt.Println(output)
}

func Worker(tasks chan Task, results chan *Result, options Option) {
    for task := range tasks {
    scan:
        // fmt.Printf("host: %s, port: %d, ssl: %v\n", task.getHost(), task.getService().port, task.getService().ssl);
        responseData, status, banner, err := task.Scan()
        if err != nil && options.Failover && task.NeedReschedule() {
            // fmt.Printf("Reschedule task %s:%d...\n", task.getHost(), task.getService().port)
            // Re-schedule the task
            task.Schedule()
            goto scan
        }

        results <- &Result{ task, responseData, status, banner, err }
    }
}

func StartScan(hosts []string, services []ServicePort, options Option) {
    var lock sync.WaitGroup
    tasks := make(chan Task, options.Threads)
    results := make(chan *Result)

    for i := 0; i < options.Threads; i++ {
        go Worker(tasks, results, options)
    }

    lock.Add(1)
    go func() {
        var writer *goterminal.Writer
        // Calculating the number of tasks
        totalTask := len(hosts) * len(services)

        if ! options.RedirectOutput && IsPty() {
            writer = goterminal.New(os.Stdout)
            fmt.Fprintf(writer, "Scanning (0/%d) services...\n", totalTask)
            writer.Print()
        }

        for i := 1; i <= totalTask; i++ {
            result := <- results

            if writer != nil {
                writer.Clear()
            }

            if result.Error == nil {
                Present(result)
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
            if options.TransportLayerScan {
                tasks <- &TransportLayerScanTask { host, service, options.Timeout }
            } else {
                tasks <- &HttpScanTask { host, service, options.ProxyURL, options.Timeout, false }
            }
        }
    }

    lock.Wait()

    close(tasks)
    close(results)
}

// This works on Unix* system only :(
func IsPty() bool {
    file, err := os.Stdin.Stat()
    if err != nil {
        return false
    }

    return (file.Mode() & os.ModeCharDevice) != 0
}

func NextAddr(address []byte) {
    for i := len(address) - 1; i >= 0; i-- {
        address[i]++
        if address[i] > 0 {
            break
        }
    }
}

func IsReserveAddr(address []byte) bool {
    return address[3] == 0 || address[3] == 0xff
}

func ParseTarget(target string) []string {
    var result []string
    pattern := regexp.MustCompile(`([0-9]+\.){3}[0-9]+/[0-9]{1,2}`)
    if pattern.MatchString(target) {
        ip, subNet, _ := net.ParseCIDR(target)
        for address := ip.Mask(subNet.Mask); subNet.Contains(address); NextAddr(address) {
            if IsReserveAddr(address) {
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
func ParsePort(ports string) []ServicePort {
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

func InitArguments() (Option, []string) {
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
    options, targets := InitArguments()

    if len(options.LogFilename) > 0 {
        handle, err := os.OpenFile(options.LogFilename, os.O_RDWR | os.O_CREATE, 0755)
        if err != nil {
            log.Fatal(err)
        }

        os.Stdout = handle
        options.RedirectOutput = true
    }

    if options.Filename != "" {
        read := ReadTarget(options.Filename)
        targets = append(targets, read...)
    }

    if options.Proxy != "" {
        proxyURL, err := url.Parse(options.Proxy)
        if err != nil {
            log.Fatal("Invalid proxy address " + options.Proxy)
        }
        options.ProxyURL = proxyURL
    }

    if len(targets) == 0 {
        log.Fatal("No targets specified")
    }

    for _, target := range targets {
        // Parsing the targets before launch the scanning in case there are CIDRs in target hosts
        for _, host := range ParseTarget(target) {
            hosts = append(hosts, host)
        }
    }

    services := ParsePort(options.Ports)

    StartScan(hosts, services, options)
}
