// Command agglog implements centralized log viewer which tails logs of multiple
// connected collectors
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/artyom/autoflags"
	"github.com/artyom/httpgzip"
	"golang.org/x/net/websocket"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
)

func main() {
	if len(os.Args) < 2 {
		os.Stderr.WriteString(usageBasic)
		os.Exit(2)
	}
	flag.Usage = usage(os.Args[1])
	var err error
	os.Args = os.Args[1:]
	switch os.Args[0] {
	default:
		os.Stderr.WriteString(usageBasic)
		os.Exit(2)
	case "client":
		args := clientArgs{Addr: "localhost:9999"}
		if name, err := os.Hostname(); err == nil {
			args.Host = name
		}
		autoflags.Parse(&args)
		err = runClient(args, flag.Args())
	case "server":
		args := serverArgs{
			ClientAddr: "localhost:9999",
			PublicAddr: "localhost:8081",
			Auth:       os.Getenv("AGGLOG_AUTH"),
		}
		autoflags.Parse(&args)
		err = runServer(args)
	}
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

type serverArgs struct {
	ClientAddr string `flag:"addr.sink,address for collectors"`
	PublicAddr string `flag:"addr.public,web UI address for users"`
	Auth       string `flag:"auth,hex-encoded sha256 of user:password, empty is no auth ($AGGLOG_AUTH env)"`
}

func runServer(args serverArgs) error {
	var auth []byte
	if args.Auth != "" {
		var err error
		if auth, err = hex.DecodeString(args.Auth); err != nil {
			return xerrors.Errorf("bad auth value: %v", err)
		}
		if len(auth) != sha256.Size {
			return xerrors.New("bad auth value: wrong size")
		}
	}
	s := &server{auth: auth}
	var collHandler websocket.Handler = func(ws *websocket.Conn) {
		if err := s.handleCollector(ws); err != nil {
			log.Print(err)
		}
	}
	collSrv := &http.Server{
		Addr:              args.ClientAddr,
		Handler:           collHandler,
		ReadHeaderTimeout: time.Second,
	}
	userSrv := &http.Server{
		Addr:         args.PublicAddr,
		Handler:      httpgzip.New(s),
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 20 * time.Second,
	}
	group, ctx := errgroup.WithContext(context.Background())
	group.Go(userSrv.ListenAndServe)
	group.Go(collSrv.ListenAndServe)
	group.Go(func() error {
		<-ctx.Done()
		collSrv.Close()
		userSrv.Close()
		return nil
	})
	return group.Wait()
}

type server struct {
	auth []byte // sha256 sum of username+":"+password, nil means no auth
	mu   sync.Mutex
	cs   map[string]collSession // key is hostname
}

// registerCollector registers collector session and returns closure to
// de-register it and channel to receive tailReqs from clients. It only returns
// error if collector for given key already registered.
func (s *server) registerCollector(key string, logs []string) (func(), <-chan tailReq, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cs == nil {
		s.cs = make(map[string]collSession)
	}
	if _, ok := s.cs[key]; ok {
		return nil, nil, xerrors.Errorf("collector for hostname %q is already registered", key)
	}
	ch := make(chan tailReq, 1)
	s.cs[key] = collSession{logs: logs, reqs: ch}
	return func() { s.mu.Lock(); defer s.mu.Unlock(); delete(s.cs, key) }, ch, nil
}

type collSession struct {
	logs []string
	reqs chan tailReq
}

type tailReq struct {
	name     string // log name
	callback func([]byte)
}

// groupedCollectors returns list of collectors grouped by their role depending
// on what logs they publish.
func (s *server) groupedCollectors() []colGroup {
	m := make(map[string][]string)
	s.mu.Lock()
	for name, cs := range s.cs {
		groupName := "Other"
		for _, log := range cs.logs {
			if strings.HasSuffix(log, "/frontend/current") {
				groupName = "Frontends"
				break
			}
			if strings.HasSuffix(log, "/backend/current") {
				groupName = "Backends"
				break
			}
		}
		m[groupName] = append(m[groupName], name)
	}
	s.mu.Unlock()
	out := make([]colGroup, 0, len(m))
	for name, hosts := range m {
		sort.Strings(hosts)
		out = append(out, colGroup{Name: name, Hosts: hosts})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type colGroup struct {
	Name  string
	Hosts []string
}

// knownLogs returns list of logs for given registered collector. If no such
// collector found, slice would be nil
func (s *server) knownLogs(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.cs[name]
	if !ok {
		return nil
	}
	return cs.logs
}

// askForLog pushes request for log to given key/logName pair. It does not wait
// for fn to be called, but blocks either until collector session receives
// request or ctx is canceled. It may return error if ctx is canceled, or no
// matching key/logName found. Errors can be safely shown back to user.
func (s *server) askForLog(ctx context.Context, key, logName string, fn func([]byte)) error {
	s.mu.Lock()
	cs, ok := s.cs[key]
	s.mu.Unlock()
	if !ok {
		return xerrors.New("no such server found")
	}
	var found bool
	for _, name := range cs.logs {
		if name == logName {
			found = true
			break
		}
	}
	if !found {
		return xerrors.New("no such log found on this server")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case cs.reqs <- tailReq{name: logName, callback: fn}:
		return nil
	}
}

// ServeHTTP handles user requests
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/favicon.ico" {
		http.NotFound(w, r)
		return
	}
	if s.auth != nil {
		u, p, ok := r.BasicAuth()
		got := sha256.Sum256([]byte(u + ":" + p))
		if !ok || subtle.ConstantTimeCompare(s.auth, got[:]) == 0 {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("X-Frame-Options", "sameorigin")
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	key, logName := r.Form.Get("host"), r.Form.Get("log")
	if key == "" {
		indexGrouped.Execute(w, s.groupedCollectors())
		return
	}
	if logName == "" {
		indexHost.Execute(w, struct {
			Host string
			Logs []string
		}{Host: key, Logs: s.knownLogs(key)})
		return
	}
	ch := make(chan []byte, 1)
	fn := func(b []byte) {
		select {
		case ch <- b:
		default:
		}
	}
	if err := s.askForLog(r.Context(), key, logName, fn); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	select {
	case <-r.Context().Done():
		panic(http.ErrAbortHandler)
	case b := <-ch:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Refresh", "120") // TODO: maybe remove?
		w.Write(b)
	}
}

// handleCollector handles collector sessions
func (s *server) handleCollector(ws *websocket.Conn) error {
	defer ws.Close()
	// 1. receive single json message holding hostname and list of logs, put
	// them into s.cs map. Defer removal from s.cs map.
	spec := collectorSpec{}
	if err := websocket.JSON.Receive(ws, &spec); err != nil {
		return xerrors.Errorf("collectorSpec receive: %v", err)
	}
	if spec.Hostname == "" {
		return xerrors.New("collectorSpec has empty hostname")
	}
	if len(spec.Logs) == 0 {
		return xerrors.Errorf("collectorSpec for host %q has empty logs", spec.Hostname)
	}
	sort.Strings(spec.Logs)
	dereg, reqs, err := s.registerCollector(spec.Hostname, spec.Logs)
	if err != nil {
		return err
	}
	defer dereg()
	// 2. keep connection alive by sending ping messages
	// 3. when client requests logs (receive from reqs chan), send string
	// message with log name from request
	// 4. wait for []byte payload which holds log tail, call request
	// callback with this payload
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case r := <-reqs:
			if err := websocket.Message.Send(ws, r.name); err != nil {
				return xerrors.Errorf("tail request for log %q: %v", r.name, err)
			}
			var data []byte
			if err := websocket.Message.Receive(ws, &data); err != nil {
				return xerrors.Errorf("tail response for log %q: %v", r.name, err)
			}
			r.callback(data)
		case <-ticker.C:
			if err := pinger.Send(ws, nil); err != nil {
				return xerrors.Errorf("ping: %v", err)
			}
		}
	}
}

type collectorSpec struct {
	Hostname string
	Logs     []string // sorted
}

type clientArgs struct {
	Addr string `flag:"addr,server address"`
	Host string `flag:"hostname"`
}

func runClient(args clientArgs, names []string) error {
	if len(names) == 0 {
		return xerrors.New("client should expose at least one log file")
	}
	if args.Host == "" {
		return xerrors.New("hostname cannot be empty")
	}
	sort.Strings(names)
	coll := collector{collectorSpec{Hostname: args.Host, Logs: names}}
	addr := args.Addr
	if !strings.HasPrefix(addr, "wss://") && !strings.HasPrefix(addr, "ws://") {
		addr = "ws://" + addr
	}
	delay := 3 * time.Second
	for {
		if err := coll.connectAndServe(addr); err != nil {
			log.Printf("%v, retrying in %v", err, delay)
		}
		time.Sleep(delay)
	}
}

type collector struct {
	collectorSpec
}

func (c collector) connectAndServe(addr string) error {
	ws, err := websocket.Dial(addr, "", "http://localhost/")
	if err != nil {
		return err
	}
	defer ws.Close()
	if err := websocket.JSON.Send(ws, c.collectorSpec); err != nil {
		return xerrors.Errorf("spec send: %v", err)
	}
	var name string
	for {
		if err := websocket.Message.Receive(ws, &name); err != nil {
			return xerrors.Errorf("log name receive: %v", err)
		}
		if !c.knownLog(name) {
			if err := websocket.Message.Send(ws, []byte("unknown log requested")); err != nil {
				return xerrors.Errorf("reply send: %v", err)
			}
			continue
		}
		b, err := tail(name)
		if err != nil {
			b = []byte("error reading log: " + err.Error())
		} else {
			// cut potentially incomplete first line
			if i := bytes.IndexByte(b, '\n'); i > 0 && i < 1024 && i+1 != len(b) {
				b = b[i+1:]
			}
		}
		if err := websocket.Message.Send(ws, b); err != nil {
			return xerrors.Errorf("reply send: %v", err)
		}
	}
}

func tail(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const size = 4096
	var b []byte
	if fi.Size() > size {
		if _, err := f.Seek(-size, io.SeekEnd); err != nil {
			return nil, err
		}
		b = make([]byte, size)
	} else {
		b = make([]byte, int(fi.Size()))
	}
	_, err = io.ReadFull(f, b)
	return b, err
}

// knownLog returns whether collector exposes log with given name
func (c collector) knownLog(name string) bool {
	i := sort.Search(len(c.Logs), func(i int) bool { return c.Logs[i] >= name })
	return i < len(c.Logs) && c.Logs[i] == name
}

const usageBasic = `Usage: agglog [client|server] [flags]
`

func usage(name string) func() {
	return func() {
		switch name {
		case "client":
			fmt.Fprintf(flag.CommandLine.Output(), "Usage: agglog %s [flags] log files\n", name)
		default:
			fmt.Fprintf(flag.CommandLine.Output(), "Usage: agglog %s [flags]\n", name)
		}
		flag.PrintDefaults()
	}
}

var indexGrouped = template.Must(template.New("index").Parse(`<!doctype html>
<head><meta charset="utf-8"><title>Server index</title></head>
<body style="line-height:140%;font-family:monospace">
<p>List of currently connected servers:</p>
{{range .}}{{.Name}}:
<ul>
{{range .Hosts}}<li><a href="?host={{.}}">{{.}}</a></li>
{{end}}</ul>
{{end}}
`))

var indexHost = template.Must(template.New("indexHost").Parse(`<!doctype html>
<head><meta charset="utf-8"><title>{{.Host}} logs index</title></head>
<body style="line-height:140%;font-family:monospace">
<p>List of <mark>{{.Host}}</mark> logs:</p>
<ul>{{$host := .Host}}
{{range .Logs}}<li><a href="?host={{$host}}&log={{.}}">{{.}}</a></li>
{{end}}
</ul>
`))

// pinger is a websocket.Codec which only sends unsolicited Pong frames
// per https://tools.ietf.org/html/rfc6455#section-5.5.3
//
//	A Pong frame MAY be sent unsolicited.
//	This serves as a unidirectional heartbeat.
//	A response to an unsolicited Pong frame is
//	not expected.
var pinger = websocket.Codec{
	Marshal: func(v interface{}) (data []byte, payloadType byte, err error) {
		return []byte{}, websocket.PongFrame, nil
	},
	Unmarshal: func(data []byte, payloadType byte, v interface{}) error {
		return xerrors.New("intentionally not implemented")
	},
}
