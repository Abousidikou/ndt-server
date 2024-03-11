package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"

	//"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/m-lab/access/controller"
	"github.com/m-lab/access/token"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/ndt-server/logging"
	ndt5handler "github.com/m-lab/ndt-server/ndt5/handler"
	"github.com/m-lab/ndt-server/ndt5/plain"
	"github.com/m-lab/ndt-server/ndt7/handler"
	"github.com/m-lab/ndt-server/ndt7/listener"

	//"github.com/m-lab/ndt-server/ndt7/results"
	"github.com/m-lab/ndt-server/ndt7/spec"
	"github.com/m-lab/ndt-server/platformx"
	"github.com/m-lab/ndt-server/version"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	logquic "github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/xyproto/sheepcounter"
)

var (
	// Flags that can be passed in on the command line
	quicwebAddr       = flag.String("quicwebAddr", ":4448", "The address and port to use for the quic web test")
	quiccmdAddr       = flag.String("quiccmdAddr", ":4447", "The address and port to use for the quic test in cmd line")
	ndt7Addr          = flag.String("ndt7_addr", ":443", "The address and port to use for the ndt7 test")
	ndt7AddrCleartext = flag.String("ndt7_addr_cleartext", ":80", "The address and port to use for the ndt7 cleartext test")
	ndt5Addr          = flag.String("ndt5_addr", ":3001", "The address and port to use for the unencrypted ndt5 test")
	ndt5WsAddr        = flag.String("ndt5_ws_addr", "127.0.0.1:3002", "The address and port to use for the ndt5 WS test")
	ndt5WssAddr       = flag.String("ndt5_wss_addr", ":3010", "The address and port to use for the ndt5 WSS test")
	certFile          = flag.String("cert", "", "The file with server certificates in PEM format.")
	keyFile           = flag.String("key", "", "The file with server key in PEM format.")
	tlsVersion        = flag.String("tls.version", "", "Minimum TLS version. Valid values: 1.2 or 1.3")
	dataDir           = flag.String("datadir", "/var/spool/ndt", "The directory in which to write data files")
	htmlDir           = flag.String("htmldir", "html", "The directory from which to serve static web content.")
	tokenVerifyKey    = flagx.FileBytesArray{}
	tokenRequired5    bool
	tokenRequired7    bool
	tokenMachine      string
	canaryRelease     bool

	// A metric to use to signal that the server is in lame duck mode.
	lameDuck = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lame_duck_experiment",
		Help: "Indicates when the server is in lame duck",
	})

	// Context for the whole program.
	ctx, cancel = context.WithCancel(context.Background())
)

func init() {
	flag.Var(&tokenVerifyKey, "token.verify-key", "Public key for verifying access tokens")
	flag.BoolVar(&tokenRequired5, "ndt5.token.required", false, "Require access token in NDT5 requests")
	flag.BoolVar(&tokenRequired7, "ndt7.token.required", false, "Require access token in NDT7 requests")
	flag.StringVar(&tokenMachine, "token.machine", "", "Use given machine name to verify token claims")
	flag.BoolVar(&canaryRelease, "canary", false, "Add -canary to server version in saved measurements")
}

func catchSigterm() {
	// Disable lame duck status.
	lameDuck.Set(0)

	// Register channel to receive SIGTERM events.
	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, syscall.SIGTERM)

	// Wait until we receive a SIGTERM or the context is canceled.
	select {
	case <-c:
		fmt.Println("Received SIGTERM")
	case <-ctx.Done():
		fmt.Println("Canceled")
	}
	// Set lame duck status. This will remain set until exit.
	lameDuck.Set(1)
	// When we receive a second SIGTERM, cancel the context and shut everything
	// down. This should cause main() to exit cleanly.
	select {
	case <-c:
		fmt.Println("Received SIGTERM")
		cancel()
	case <-ctx.Done():
		fmt.Println("Canceled")
	}
}

func init() {
	log.SetFlags(log.LUTC | log.LstdFlags | log.Lshortfile)
}

// httpServer creates a new *http.Server with explicit Read and Write timeouts.
func httpServer(addr string, handler http.Handler) *http.Server {
	tlsconf := &tls.Config{}
	switch *tlsVersion {
	case "1.3":
		tlsconf = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	case "1.2":
		tlsconf = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	return &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsconf,
		// NOTE: set absolute read and write timeouts for server connections.
		// This prevents clients, or middleboxes, from opening a connection and
		// holding it open indefinitely. This applies equally to TLS and non-TLS
		// servers.
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}
}

/*********************** My Functions ********************************/

var msgSize = 1 << 25 //33 MB
var msgSizeweb = 1 << 13
var msg = generatePRData(int(msgSize))
var msgWeb = generatePRData(int(msgSizeweb))
var downloadSpeed string
var uploadSpeed string
var downDatalengh int64
var downSpeed int64
var durationDown int64
var numberStream int
var dataSize int

const ratio = 1048576

var upDatalengh int
var upSpeed int64

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

type QuicData struct {
	Date string `json:"Date"`
	Down string `json:"Down"`
	Up   string `json:"Up"`
}

// Generate data Byte from interger(lengh)
func generatePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

// NewBufferedWriteCloser creates an io.WriteCloser from a bufio.Writer and an io.Closer
func NewBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{
		Writer: writer,
		Closer: closer,
	}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	tlsCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func downloadTest(rw http.ResponseWriter, req *http.Request) {
	fmt.Println("Download Subtest")
	sc := sheepcounter.New(rw)
	sc.Write(msgWeb)
	downDatalengh += sc.Counter()
	fmt.Println("COUNTED:", downDatalengh) // Counts the bytes sent, for this response only
}

func getDownSpeed(rw http.ResponseWriter, req *http.Request) {
	timeString := req.FormValue("id")
	fmt.Println("timeString: ", timeString)
	t, _ := strconv.ParseFloat(timeString, 64)
	durationDown = int64(t)
	downSpeed = ((int64(downDatalengh*8) / int64(durationDown)) * 1000) / 1000000
	fmt.Fprintf(rw, strconv.FormatInt(downSpeed, 10))
	fmt.Println(downDatalengh, downSpeed, int64(durationDown))
	downDatalengh = 0
}

func uploadTest(rw http.ResponseWriter, req *http.Request) {
	body := &bytes.Buffer{}
	_, err := io.Copy(body, req.Body)
	if err != nil {
		log.Fatal("request", err)
	}
	upDatalengh += body.Len()
}

func getUpSpeed(rw http.ResponseWriter, req *http.Request) {
	timeString := req.FormValue("id")
	//fmt.Println(reflect.TypeOf(timeString))
	t, _ := strconv.ParseFloat(timeString, 64)
	upSpeed = (((int64(upDatalengh) * 8) / int64(t)) * 1000) / 1000000
	fmt.Println("upSpeed: ", upSpeed)
	fmt.Fprintf(rw, strconv.FormatInt(int64(upDatalengh), 10))
}

/************************  End Functions ******************************/
func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not parse env args")
	// Append -canary to version string if needed.
	if canaryRelease {
		version.Version += "-canary"
	}
	// TODO: Decide if signal handling is the right approach here.
	go catchSigterm()

	promSrv := prometheusx.MustServeMetrics()
	defer promSrv.Close()

	platformx.WarnIfNotFullySupported()

	// Setup sequence of access control http.Handlers. NewVerifier errors are
	// not fatal as long as tokens are not required. This allows access tokens
	// to be optional for users who have no need for access tokens. An invalid
	// verifier is handled safely by Setup and only prints a warning when access
	// token verification is disabled.
	v, err := token.NewVerifier(tokenVerifyKey.Get()...)
	if (tokenRequired5 || tokenRequired7) && err != nil {
		rtx.Must(err, "Failed to load verifier for when tokens are required")
	}
	// NDT5 uses a raw server, which requires tx5. NDT7 is HTTP only.
	ac5, tx5 := controller.Setup(ctx, v, tokenRequired5, tokenMachine)
	ac7, _ := controller.Setup(ctx, v, tokenRequired7, tokenMachine)

	// The ndt5 protocol serving non-HTTP-based tests - forwards to Ws-based
	// server if the first three bytes are "GET".
	ndt5Server := plain.NewServer(*dataDir+"/ndt5", *ndt5WsAddr)
	rtx.Must(
		ndt5Server.ListenAndServe(ctx, *ndt5Addr, tx5),
		"Could not start raw server")

	// The ndt5 protocol serving Ws-based tests. Most clients are hard-coded to
	// connect to the raw server, which will forward things along.
	ndt5WsMux := http.NewServeMux()
	ndt5WsMux.Handle("/", http.FileServer(http.Dir(*htmlDir)))
	ndt5WsMux.Handle("/ndt_protocol", ndt5handler.NewWS(*dataDir+"/ndt5"))
	controller.AllowPathLabel("/ndt_protocol")
	ndt5WsServer := httpServer(
		*ndt5WsAddr,
		// NOTE: do not use `ac.Then()` to prevent 'double jeopardy' for
		// forwarded clients when txcontroller is enabled.
		logging.MakeAccessLogHandler(ndt5WsMux),
	)
	log.Println("About to listen for unencrypted ndt5 NDT tests on " + *ndt5WsAddr)
	rtx.Must(listener.ListenAndServeAsync(ndt5WsServer), "Could not start unencrypted ndt5 NDT server")
	defer ndt5WsServer.Close()

	// The ndt7 listener serving up NDT7 tests, likely on standard ports.
	ndt7Mux := http.NewServeMux()
	ndt7Mux.HandleFunc("/params", func(w http.ResponseWriter, r *http.Request) {
		numberStream, _ = strconv.Atoi(r.FormValue("nStream"))
		dataSize, _ = strconv.Atoi(r.FormValue("dataSize"))
		fmt.Fprintf(w, "Paramaters Received")
	})
	ndt7Mux.HandleFunc("/testFinished", func(w http.ResponseWriter, r *http.Request) {
		downloadSpeed = r.FormValue("down")
		m := time.Now()
		fmt.Println(m.Year(), int(m.Month()), m.Day())
		mon := ""
		if int(m.Month())+1 < 10 {
			mon = "0" + strconv.Itoa(int(m.Month()))
		} else {
			mon = strconv.Itoa(int(m.Month()))
		}
		quicD := QuicData{
			Date: m.String()[:11],
			Down: downloadSpeed,
			Up:   uploadSpeed,
		}
		fmt.Println("Struct: ", quicD)
		file, errJson := json.Marshal(quicD)
		if errJson != nil {
			fmt.Println(errJson)
		}
		fmt.Println("File:", string(file))
		err := os.MkdirAll("datadir/quic/"+strconv.Itoa(m.Year())+"/"+mon+"/"+strconv.Itoa(m.Day()), 0777)
		if err != nil {
			fmt.Println(err)
		}
		fi := fmt.Sprintf("datadir/quic/"+strconv.Itoa(m.Year())+"/"+mon+"/"+strconv.Itoa(m.Day())+"/quicTest_%s.json", m.String())
		fmt.Println("Filename: ", fi)
		errW := ioutil.WriteFile(fi, file, 0777)
		if errW != nil {
			fmt.Println(errW)
			return
		}
		fmt.Fprintf(w, uploadSpeed)
	})
	ndt7Mux.Handle("/", http.FileServer(http.Dir(*htmlDir)))
	ndt7Handler := &handler.Handler{
		DataDir:      *dataDir,
		SecurePort:   *ndt7Addr,
		InsecurePort: *ndt7AddrCleartext,
	}
	ndt7Mux.Handle(spec.DownloadURLPath, http.HandlerFunc(ndt7Handler.Download))
	ndt7Mux.Handle(spec.UploadURLPath, http.HandlerFunc(ndt7Handler.Upload))
	controller.AllowPathLabel(spec.DownloadURLPath)
	controller.AllowPathLabel(spec.UploadURLPath)
	ndt7ServerCleartext := httpServer(
		*ndt7AddrCleartext,
		ac7.Then(logging.MakeAccessLogHandler(ndt7Mux)),
	)
	log.Println("About to listen for ndt7 cleartext tests on " + *ndt7AddrCleartext)
	rtx.Must(listener.ListenAndServeAsync(ndt7ServerCleartext), "Could not start ndt7 cleartext server")
	defer ndt7ServerCleartext.Close()

	// Only start TLS-based services if certs and keys are provided
	if *certFile != "" && *keyFile != "" {
		// The ndt5 protocol serving WsS-based tests.
		ndt5WssMux := http.NewServeMux()
		ndt5WssMux.Handle("/", http.FileServer(http.Dir(*htmlDir)))
		ndt5WssMux.Handle("/ndt_protocol", ndt5handler.NewWSS(*dataDir+"/ndt5", *certFile, *keyFile))
		ndt5WssServer := httpServer(
			*ndt5WssAddr,
			ac5.Then(logging.MakeAccessLogHandler(ndt5WssMux)),
		)
		log.Println("About to listen for ndt5 WsS tests on " + *ndt5WssAddr)
		rtx.Must(listener.ListenAndServeTLSAsync(ndt5WssServer, *certFile, *keyFile), "Could not start ndt5 WsS server")
		defer ndt5WssServer.Close()

		// The ndt7 listener serving up WSS based tests
		ndt7Server := httpServer(
			*ndt7Addr,
			ac7.Then(logging.MakeAccessLogHandler(ndt7Mux)),
		)
		log.Println("About to listen for ndt7 tests on " + *ndt7Addr)
		rtx.Must(listener.ListenAndServeTLSAsync(ndt7Server, *certFile, *keyFile), "Could not start ndt7 server")
		defer ndt7Server.Close()
	} else {
		log.Printf("Cert=%q and Key=%q means no TLS services will be started.\n", *certFile, *keyFile)
	}

	/****************************************** QUIC Setup  *******************************************/
	//runtime.GOMAXPROCS(4)
	//TCP AND QUIC Handler
	// Waitgroup
	var wg sync.WaitGroup
	wg.Add(2)

	//goroutine serving on 4447
	//ndt7MuxTCPQuic := http.NewServeMux()
	fmt.Println("About to setup QUIC")
	//ndt7MuxTCPQuic.Handle("/", http.FileServer(http.Dir(*htmlDir+"/stat")))
	fmt.Println("About to listening on TCP AND QUIC :4447")
	go func() {
		quicC := &quic.Config{
			//MaxIdleTimeout: 60 * time.Second,
		}

		// Qlog setup
		fmt.Println("Setting qlogs...")
		quicC.Tracer = qlog.NewTracer(func(_ logquic.Perspective, connID []byte) io.WriteCloser {
			//fmt.Println(connID)
			m := time.Now()
			fmt.Println(m.Year(), int(m.Month()), m.Day())
			mon := ""
			if int(m.Month())+1 < 10 {
				mon = "0" + strconv.Itoa(int(m.Month()))
			} else {
				mon = strconv.Itoa(int(m.Month()))
			}
			os.MkdirAll("datadir/qlogs/"+strconv.Itoa(m.Year())+"/"+mon+"/"+strconv.Itoa(m.Day()), 0777)
			filename := fmt.Sprintf("datadir/qlogs/"+strconv.Itoa(m.Year())+"/"+mon+"/"+strconv.Itoa(m.Day())+"/server_%s.qlog", time.Now().String())
			fmt.Println("Filename: ", filename)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Creating qlog file %s.\n", filename)
			return NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})

		listener, err := quic.ListenAddr(*quiccmdAddr, generateTLSConfig(), quicC)
		if err != nil {
			fmt.Println(err)
			return
		}
		//fmt.Println("Listening on ", addr)
		defer listener.Close()
		for true {
			//fmt.Println("Waiting for Test")
			sess, err := listener.Accept(context.Background())
			if err != nil {
				fmt.Println("Session creating error:", err)
				return
			}
			//fmt.Println("Connection Accepted")
			//fmt.Println(sess.ConnectionState())
			//fmt.Println("Server: ", sess.LocalAddr())
			//fmt.Println(sess.RemoteAddr())
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Println("Upload Testing...")
				var total int
				var w sync.WaitGroup
				var mu sync.Mutex
				var times []time.Duration
				for i := 0; i < numberStream; i++ {
					fmt.Println(i)
					fmt.Println("Waiting for next stream. open by peer..")
					streamUp, err := sess.AcceptStream(context.Background())
					if err != nil {
						fmt.Println(" Stream created error: ", err)
						return
					}
					// each go routine for each stream
					w.Add(1)
					go func(streamUp quic.Stream) {
						defer w.Done()
						streamUp.SetReadDeadline(time.Now().Add(13 * time.Second))
						t1 := time.Now()
						//bytesReceived, err := io.Copy(&buf, stream) //loggingWriter{stream}
						buff := make([]byte, dataSize)
						byter, _ := io.ReadFull(streamUp, buff)
						d_temp := time.Since(t1)
						fmt.Println("Bytes reveived :" + strconv.Itoa(byter))
						mu.Lock()
						times = append(times, d_temp)
						total += byter
						mu.Unlock()
					}(streamUp)
					fmt.Println("Go fun lauched with i=", i)
				}
				w.Wait()
				t := times[0]
				for ind := range times {
					if t < times[ind] {
						t = times[ind]
					}
				}
				fmt.Println("Bytes Received: ", total)
				fmt.Println("Time for receiving", t.Microseconds())
				bps := float64(total*8) / t.Seconds()
				Mbps := float64(bps / ratio)
				uploadSpeed = fmt.Sprintf("%.3f", Mbps)
				fmt.Printf("Upload Speed: %.3f Mbps\n", Mbps)

				fmt.Println("Download Testing...")
				var bytesSents int
				msg := generatePRData(dataSize)
				for i := 0; i < numberStream; i++ {
					fmt.Println(i)
					streamDown, err := sess.OpenStreamSync(context.Background())
					if err != nil {
						fmt.Println(" Stream created: ", err)
						return
					}
					defer streamDown.Close()
					fmt.Println("Stream Accepted with ID: ", streamDown.StreamID())
					w.Add(1)
					go func() {
						defer w.Done()
						streamDown.SetWriteDeadline(time.Now().Add(13 * time.Second))
						bytesSent, _ := streamDown.Write(msg)
						fmt.Println("Byte sent:", bytesSent)
						bytesSents += bytesSent
					}()
					fmt.Println("Go func lauched i=", i)
				}
				w.Wait()

				// sending download stat
				fmt.Println("Bytes Sents: ", bytesSents)

				// sending download stat
				/*d_stat, err := sess.OpenStreamSync(context.Background())
				s := fmt.Sprintf("%.3f", Mbps)
				stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
				bytesSent, _ = stream.Write([]byte(s))*/

			}()
		}

		//log.Fatal(http3.ListenAndServe(":4447", *certFile, *keyFile, ndt7MuxTCPQuic))
		wg.Done()
	}()

	// QUIC Handler goroutine serving on 4448
	fmt.Println("For Quic Only")
	ndt7MuxQuic := http.NewServeMux()
	ndt7MuxQuic.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "Welcome on Quic Api") })
	ndt7MuxQuic.HandleFunc("/download", downloadTest)
	ndt7MuxQuic.HandleFunc("/getDownSpeed", getDownSpeed)
	ndt7MuxQuic.HandleFunc("/upload", uploadTest)
	ndt7MuxQuic.HandleFunc("/getUpSpeed", getUpSpeed)
	ndt7MuxQuic.HandleFunc("/demo/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			start := time.Now()
			err := r.ParseMultipartForm(1 << 30) // 4 GB
			if err == nil {
				var file multipart.File
				var hand *multipart.FileHeader
				file, hand, err = r.FormFile("uploadfile")
				if err == nil {
					//defer file.Close()
					//var size int64
					if sizeInterface, ok := file.(Size); ok {
						_ = sizeInterface.Size() // _ == size
						//b := make([]byte, size)
						//start := time.Now()
						//i, _ := file.Read(b)
						//fmt.Println(time.Since(start))
						//fmt.Println("Size of file: ", i, " bytes")

						logFile, logerr := os.OpenFile("log.file", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
						f, err := os.OpenFile("./html/quic/data/"+hand.Filename, os.O_WRONLY|os.O_CREATE, 0666)
						if err != nil || logerr != nil {
							fmt.Println(err)
							return
						}
						defer logFile.Close()
						defer f.Close()
						// Calling Copy method with its parameters
						bytes, erro := io.Copy(f, file)
						// If error is not nil then panics
						if erro != nil {
							panic(erro)
						}

						// Prints output
						fmt.Printf("The number of bytes are: %d\n", bytes)
						fmt.Println(time.Since(start))
						logFile.WriteString("Nom du fichier: " + hand.Filename + "\n")
						logFile.WriteString("Taille du fichier: " + strconv.FormatInt(int64(bytes), 10) + " bytes\n")
						logFile.WriteString("Temps d'envoie: " + time.Since(start).String() + "\n\n")

						//file.Read(b)
						//md5 := md5.Sum(b)
						//fmt.Fprintf(w, "File Received---md5:%x---Header:%v", md5, hand.Header)
						fmt.Fprintf(w, "File Received---%v", hand.Header)
						return
					}
					err = errors.New("couldn't get uploaded file size")
				}
			}
			fmt.Printf("Error receiving upload: %#v", err)
		}
		io.WriteString(w, `<html><body><form action="/demo/upload" method="post" enctype="multipart/form-data">
				<input type="file" name="uploadfile"><br>
				<input type="submit">
			</form></body></html>`)
	})

	// Create file server handler
	direc, _ := os.Getwd()
	fs := http.FileServer(http.Dir(direc + "/html/quic/data"))
	ndt7MuxQuic.Handle("/data/", http.StripPrefix("/data", fs))
	fmt.Println("htmlDir:", *htmlDir)
	ndt7MuxQuic.Handle("/", http.FileServer(http.Dir(*htmlDir+"/quic")))

	// QUIC Server
	fmt.Println("About to listening on QUIC :4448")
	go func() {
		//log.Fatal(http3.ListenAndServe(*quicwebAddr, *certFile, *keyFile, ndt7MuxQuic))
		// QUIC COnfig setup
		/*fmt.Println("QuicConfig setup...")
		quicConf := &quic.Config{}

		// Qlog setup
		quicConf.Tracer = qlog.NewTracer(func(_ logquic.Perspective, connID []byte) io.WriteCloser {
			fmt.Println("Setting qlogs...")
			fmt.Println(connID)
			filename := fmt.Sprintf("server_%s.qlog", time.Now().String())
			f, err := os.Create("./datadir/" + filename)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Creating qlog file %s.\n", filename)
			return NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})

		// QUIC Server setup
		fmt.Println("Quic Server setup...")
		server := http3.Server{
			Server:     &http.Server{Handler: ndt7MuxQuic, Addr: ":4448"},
			QuicConfig: quicConf,
		}

		// Start listening
		fmt.Println("About to listening on QUIC :4448")
		log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))*/
		wg.Done()
	}()
	// wait until WaitGroup is done
	wg.Wait()

	/*	// QUIC COnfig setup
		fmt.Println("QuicConfig setup...")
		quicConf := &quic.Config{}

		// Qlog setup
		quicConf.Tracer = qlog.NewTracer(func(_ logquic.Perspective, connID []byte) io.WriteCloser {
			fmt.Println("Setting qlogs...")
			fmt.Println(connID)
			filename := fmt.Sprintf("server_%s.qlog", time.Now().String())
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Creating qlog file %s.\n", filename)
			return NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})

		// QUIC Server setup
		fmt.Println("Quic Server setup...")
		server := http3.Server{
			Server:     &http.Server{Handler: ndt7MuxQuic, Addr: ":4448"},
			QuicConfig: quicConf,
		}

		// Start listening
		fmt.Println("About to listening on QUIC :4448")
		log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))*/

	/********************************************************************************************/
	// Serve until the context is canceled.
	<-ctx.Done()
}
