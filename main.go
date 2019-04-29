package main

import (
    "io"
    "os"
    "fmt"
    "net"
    "flag"
    "time"
    "context"
    "syscall"
    "strings"
    "os/signal"
    "io/ioutil"
    yaml "gopkg.in/yaml.v2"
)

var SNIPort = 443
var ForwardPort = 443
var cfg conf

type conf struct {
    ForwardRules []string `yaml:"rules"`
}

var (
    cfgfile = flag.String("c", "config.yaml", "config file")
    FileLogPath = flag.String("F", "", "log to file")
    EnableDebug = flag.Bool("D", false, "Enable debug")
)

func main(){
    flag.Parse()
    data, err := ioutil.ReadFile(*cfgfile)
    if err != nil {
        serviceLogger(fmt.Sprintf("Yaml file read failed: %v", err), 31)
        os.Exit(0)
    }
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        serviceLogger(fmt.Sprintf("Yaml file unmarshal failed: %v", err), 31)
        os.Exit(0)
    }
    if(len(cfg.ForwardRules) <= 0){
        serviceLogger(fmt.Sprintf("No rules found in yaml!"), 31)
        os.Exit(0)
    }
    for _, rule := range cfg.ForwardRules {
        serviceLogger(fmt.Sprintf("Loaded rule: %v", rule), 32)
    }
    startSNIproxy()
}

func startSNIproxy(){
    _, cancel := context.WithCancel(context.Background())
    defer cancel()
    serviceLogger(fmt.Sprintf("Starting SNI Proxy on port %v", SNIPort), 0)
    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", SNIPort))
    if err != nil {
        serviceLogger(fmt.Sprintf("SNI Proxy Init failed: %v", err), 31)
        os.Exit(0)
    }
    go func(listener net.Listener) {
        defer listener.Close()
        for {
            connection, err := listener.Accept()
            if err != nil {
                serviceLogger(fmt.Sprintf("SNI Proxy Accept failed: %v", err), 31)
            }
            raddr := connection.RemoteAddr().(*net.TCPAddr)
            serviceLogger(fmt.Sprintf("Connection From %s", fmt.Sprintf("%s", raddr)), 32)
            go serve(connection, fmt.Sprintf("%s", raddr))
        }
    }(listener)
    ch := make(chan os.Signal, 2)
    signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
    select {
    case s := <-ch:
        cancel()
        fmt.Printf("\nreceived signal %s, exit.\n", s)
    }
}

func serve(c net.Conn, raddr string) {
    defer c.Close()

    buf := make([]byte, 1024)
    n, err := c.Read(buf)
    if err != nil && fmt.Sprintf("%v", err) != "EOF"{
        serviceLogger(fmt.Sprintf("SNI Proxy Serve failed: %v", err), 31)
        return
    }

    servername := getSNIServerName(buf[:n])

    if servername == "" {
        serviceDebugger(fmt.Sprintf("No SNI server name found, ignore it"), 31)
        return
    }

    for _, rule := range cfg.ForwardRules {
        if(strings.Contains(servername, rule)){
            serviceDebugger(fmt.Sprintf("Found %v, forwarding to %s:%d", servername, servername, ForwardPort), 32)
            forward(c, buf[:n], fmt.Sprintf("%s:%d", servername, ForwardPort), raddr)
        }
    }
}

func getSNIServerName(buf []byte) string {
    n := len(buf)
    if n < 5 {
        serviceDebugger(fmt.Sprintf("Not tls handshake"), 31)
        return ""
    }

    // tls record type
    if recordType(buf[0]) != recordTypeHandshake {
        serviceDebugger(fmt.Sprintf("Not tls"), 31)
        return ""
    }

    // tls major version
    if buf[1] != 3 {
        serviceDebugger(fmt.Sprintf("TLS version < 3 not supported"), 31)
        return ""
    }

    // payload length
    //l := int(buf[3])<<16 + int(buf[4])

    //log.Printf("length: %d, got: %d", l, n)

    // handshake message type
    if uint8(buf[5]) != typeClientHello {
        serviceDebugger(fmt.Sprintf("Not client hello"), 31)
        return ""
    }

    // parse client hello message

    msg := &clientHelloMsg{}

    // client hello message not include tls header, 5 bytes
    ret := msg.unmarshal(buf[5:n])
    if !ret {
        serviceDebugger(fmt.Sprintf("Parse hello message return false"), 31)
        return ""
    }
    return msg.serverName
}

func forward(conn net.Conn, data []byte, dst string, raddr string) {
    backend, err := net.Dial("tcp", dst)
    if err != nil {
        serviceLogger(fmt.Sprintf("Couldn't connect to backend, %v", err), 31)
        return
    }

    defer backend.Close()

    if _, err = backend.Write(data); err != nil {
        serviceLogger(fmt.Sprintf("Couldn't write to backend, %v", err), 31)
        return
    }

    con_chk := make(chan int)
    go ioReflector(backend, conn, false, con_chk, raddr, dst)
    go ioReflector(conn, backend, true, con_chk, raddr, dst)
    <-con_chk
}

func ioReflector(dst io.WriteCloser, src io.Reader, isToClient bool, con_chk chan int, raddr string, dsts string) {
    // Reflect IO stream to another.
    defer on_disconnect(dst, con_chk)
    written, _ := io.Copy(dst, src)
    if(isToClient){
        serviceDebugger(fmt.Sprintf("[%v] -> [%v], Written %d bytes", dsts, raddr, written), 33)
    }else{
        serviceDebugger(fmt.Sprintf("[%v] -> [%v], Written %d bytes", raddr, dsts, written), 33)  
    }
    dst.Close()
    con_chk <- 1
}

func on_disconnect(dst io.WriteCloser, con_chk chan int){
	// On Close-> Force Disconnect another pair of connection.
	dst.Close()
	con_chk <- 1
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
    if len(data) < 42 {
        return false
    }
    m.raw = data
    m.vers = uint16(data[4])<<8 | uint16(data[5])
    m.random = data[6:38]
    sessionIDLen := int(data[38])
    if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
        return false
    }
    m.sessionID = data[39 : 39+sessionIDLen]
    data = data[39+sessionIDLen:]
    if len(data) < 2 {
        return false
    }
    // cipherSuiteLen is the number of bytes of cipher suite numbers. Since
    // they are uint16s, the number must be even.
    cipherSuiteLen := int(data[0])<<8 | int(data[1])
    if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
        return false
    }
    numCipherSuites := cipherSuiteLen / 2
    m.cipherSuites = make([]uint16, numCipherSuites)
    for i := 0; i < numCipherSuites; i++ {
        m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
        if m.cipherSuites[i] == scsvRenegotiation {
            m.secureRenegotiationSupported = true
        }
    }
    data = data[2+cipherSuiteLen:]
    if len(data) < 1 {
        return false
    }
    compressionMethodsLen := int(data[0])
    if len(data) < 1+compressionMethodsLen {
        return false
    }
    m.compressionMethods = data[1 : 1+compressionMethodsLen]

    data = data[1+compressionMethodsLen:]

    m.nextProtoNeg = false
    m.serverName = ""
    m.ocspStapling = false
    m.ticketSupported = false
    m.sessionTicket = nil
    m.signatureAndHashes = nil
    m.alpnProtocols = nil
    m.scts = false

    if len(data) == 0 {
        // ClientHello is optionally followed by extension data
        return true
    }
    if len(data) < 2 {
        return false
    }

    extensionsLength := int(data[0])<<8 | int(data[1])
    data = data[2:]
    if extensionsLength != len(data) {
        return false
    }

    for len(data) != 0 {
        if len(data) < 4 {
            return false
        }
        extension := uint16(data[0])<<8 | uint16(data[1])
        length := int(data[2])<<8 | int(data[3])
        data = data[4:]
        if len(data) < length {
            return false
        }

        switch extension {
        case extensionServerName:
            d := data[:length]
            if len(d) < 2 {
                return false
            }
            namesLen := int(d[0])<<8 | int(d[1])
            d = d[2:]
            if len(d) != namesLen {
                return false
            }
            for len(d) > 0 {
                if len(d) < 3 {
                    return false
                }
                nameType := d[0]
                nameLen := int(d[1])<<8 | int(d[2])
                d = d[3:]
                if len(d) < nameLen {
                    return false
                }
                if nameType == 0 {
                    m.serverName = string(d[:nameLen])
                    // An SNI value may not include a
                    // trailing dot. See
                    // https://tools.ietf.org/html/rfc6066#section-3.
                    if strings.HasSuffix(m.serverName, ".") {
                        return false
                    }
                    break
                }
                d = d[nameLen:]
            }
        case extensionNextProtoNeg:
            if length > 0 {
                return false
            }
            m.nextProtoNeg = true
        case extensionStatusRequest:
            m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
        case extensionSupportedCurves:
            // http://tools.ietf.org/html/rfc4492#section-5.5.1
            if length < 2 {
                return false
            }
            l := int(data[0])<<8 | int(data[1])
            if l%2 == 1 || length != l+2 {
                return false
            }
            numCurves := l / 2
            m.supportedCurves = make([]CurveID, numCurves)
            d := data[2:]
            for i := 0; i < numCurves; i++ {
                m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
                d = d[2:]
            }
        case extensionSupportedPoints:
            // http://tools.ietf.org/html/rfc4492#section-5.5.2
            if length < 1 {
                return false
            }
            l := int(data[0])
            if length != l+1 {
                return false
            }
            m.supportedPoints = make([]uint8, l)
            copy(m.supportedPoints, data[1:])
        case extensionSessionTicket:
            // http://tools.ietf.org/html/rfc5077#section-3.2
            m.ticketSupported = true
            m.sessionTicket = data[:length]
        case extensionSignatureAlgorithms:
            // https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
            if length < 2 || length&1 != 0 {
                return false
            }
            l := int(data[0])<<8 | int(data[1])
            if l != length-2 {
                return false
            }
            n := l / 2
            d := data[2:]
            m.signatureAndHashes = make([]signatureAndHash, n)
            for i := range m.signatureAndHashes {
                m.signatureAndHashes[i].hash = d[0]
                m.signatureAndHashes[i].signature = d[1]
                d = d[2:]
            }
        case extensionRenegotiationInfo:
            if length == 0 {
                return false
            }
            d := data[:length]
            l := int(d[0])
            d = d[1:]
            if l != len(d) {
                return false
            }

            m.secureRenegotiation = d
            m.secureRenegotiationSupported = true
        case extensionALPN:
            if length < 2 {
                return false
            }
            l := int(data[0])<<8 | int(data[1])
            if l != length-2 {
                return false
            }
            d := data[2:length]
            for len(d) != 0 {
                stringLen := int(d[0])
                d = d[1:]
                if stringLen == 0 || stringLen > len(d) {
                    return false
                }
                m.alpnProtocols = append(m.alpnProtocols, string(d[:stringLen]))
                d = d[stringLen:]
            }
        case extensionSCT:
            m.scts = true
            if length != 0 {
                return false
            }
        }
        data = data[length:]
    }

    return true
}

func serviceLogger(log string, color int){
    log = strings.Replace(log, "\n", "", -1)
    log = strings.Join([]string{time.Now().Format("2006/01/02 15:04:05"), " ", log}, "")
    if(color == 0){
        fmt.Printf("%s\n", log)
    }else{
        fmt.Printf("%c[1;0;%dm%s%c[0m\n", 0x1B, color, log, 0x1B)
    }
    if(*FileLogPath != ""){
        fd, _ := os.OpenFile(*FileLogPath, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0644)  
        fd_time := time.Now().Format("2006/01/02-15:04:05");  
        fd_content := strings.Join([]string{fd_time, "  ", log, "\n"}, "")  
        buf := []byte(fd_content)  
        fd.Write(buf)  
        fd.Close()
    }
}

func serviceDebugger(log string, color int){
    if(*EnableDebug){
        log = strings.Replace(log, "\n", "", -1)
        log = strings.Join([]string{time.Now().Format("2006/01/02 15:04:05"), " [Debug] ", log}, "")
        if(color == 0){
            fmt.Printf("%s\n", log)
        }else{
            fmt.Printf("%c[1;0;%dm%s%c[0m\n", 0x1B, color, log, 0x1B)
        }
        if(*FileLogPath != ""){
            fd, _ := os.OpenFile(*FileLogPath, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0644)  
            fd_time := time.Now().Format("2006/01/02-15:04:05");  
            fd_content := strings.Join([]string{fd_time, "  ", log, "\n"}, "")  
            buf := []byte(fd_content)  
            fd.Write(buf)  
            fd.Close()
        }
    }
}