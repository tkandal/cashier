package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/tkandal/cashier/server/auth/dataporten"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gorilla/csrf"

	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"

	"go4.org/wkfs"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"

	wkfscache "github.com/nsheridan/autocert-wkfs-cache"
	"github.com/sid77/drop"
	"github.com/tkandal/cashier/lib"
	"github.com/tkandal/cashier/server/auth"
	"github.com/tkandal/cashier/server/auth/github"
	"github.com/tkandal/cashier/server/auth/gitlab"
	"github.com/tkandal/cashier/server/auth/google"
	"github.com/tkandal/cashier/server/auth/microsoft"
	"github.com/tkandal/cashier/server/config"
	"github.com/tkandal/cashier/server/metrics"
	"github.com/tkandal/cashier/server/signer"
	"github.com/tkandal/cashier/server/store"
)

const (
	sigIntExit    = 130
	minTLSversion = tls.VersionTLS12
)

var (
	catchSignals = []os.Signal{syscall.SIGHUP, os.Interrupt, syscall.SIGTERM}
	idleClosed   = make(chan struct{})
)

func handleInterrupts(s *http.Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, catchSignals...)
	select {
	case sig := <-sigChan:

		log.Printf("received signal %v; hold on to your devices ...\n", sig)
		if sig != os.Interrupt {
			defer close(idleClosed)
		}
		signal.Reset(catchSignals...)

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(s.ReadTimeout))
		defer cancel()

		if err := s.Shutdown(ctx); err != nil {
			log.Printf("stop http server failed; error = %v\n", err)
			return
		}
		log.Printf("http server is shut down\n")

		if sig == os.Interrupt {
			if err := signalProc(os.Getpid(), os.Interrupt); err != nil {
				os.Exit(sigIntExit)
			}
		}
	}
}

func loadCerts(certFile, keyFile string) (tls.Certificate, error) {
	key, err := wkfs.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "error reading TLS private key")
	}
	cert, err := wkfs.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, errors.Wrap(err, "error reading TLS certificate")
	}
	return tls.X509KeyPair(cert, key)
}

// Run the server.
func Run(conf *config.Config) {
	var err error

	laddr := fmt.Sprintf("%s:%d", conf.Server.Addr, conf.Server.Port)
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(errors.Wrapf(err, "unable to listen on %s:%d", conf.Server.Addr, conf.Server.Port))
	}

	tlsConfig := &tls.Config{MinVersion: minTLSversion}
	if conf.Server.UseTLS {
		if conf.Server.LetsEncryptServername != "" {
			m := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(conf.Server.LetsEncryptServername),
			}
			if conf.Server.LetsEncryptCache != "" {
				m.Cache = wkfscache.Cache(conf.Server.LetsEncryptCache)
			}
			tlsConfig = m.TLSConfig()
		} else {
			if conf.Server.TLSCert == "" || conf.Server.TLSKey == "" {
				log.Fatal("TLS cert or key not specified in config")
			}
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			tlsConfig.Certificates[0], err = loadCerts(conf.Server.TLSCert, conf.Server.TLSKey)
			if err != nil {
				log.Fatal(errors.Wrap(err, "unable to create TLS listener"))
			}
		}
		l = tls.NewListener(l, tlsConfig)
	}

	if conf.Server.User != "" {
		log.Print("Dropping privileges...")
		if err := drop.DropPrivileges(conf.Server.User); err != nil {
			log.Fatal(errors.Wrap(err, "unable to drop privileges"))
		}
	}

	// Unprivileged section
	metrics.Register()

	var authprovider auth.Provider
	switch conf.Auth.Provider {
	case "github":
		authprovider, err = github.New(conf.Auth)
	case "gitlab":
		authprovider, err = gitlab.New(conf.Auth)
	case "google":
		authprovider, err = google.New(conf.Auth)
	case "microsoft":
		authprovider, err = microsoft.New(conf.Auth)
	case "dataporten":
		authprovider, err = dataporten.New(conf.Auth)
	default:
		log.Fatalf("Unknown provider %s\n", conf.Auth.Provider)
	}
	if err != nil {
		log.Fatal(errors.Wrapf(err, "unable to use provider '%s'", conf.Auth.Provider))
	}

	keysigner, err := signer.New(conf.SSH)
	if err != nil {
		log.Fatal(err)
	}

	certstore, err := store.New(conf.Server.Database)
	if err != nil {
		log.Fatal(err)
	}

	ctx := &app{
		cookiestore:   sessions.NewCookieStore([]byte(conf.Server.CookieSecret)),
		requireReason: conf.Server.RequireReason,
		keysigner:     keysigner,
		certstore:     certstore,
		authprovider:  authprovider,
		config:        conf.Server,
		router:        mux.NewRouter(),
	}
	ctx.cookiestore.Options = &sessions.Options{
		MaxAge:   900,
		Path:     "/",
		Secure:   conf.Server.UseTLS,
		HttpOnly: true,
	}

	logfile := os.Stderr
	if conf.Server.HTTPLogFile != "" {
		// #nosec
		logfile, err = os.OpenFile(conf.Server.HTTPLogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, os.FileMode(0640))
		if err != nil {
			log.Printf("error opening log: %v. logging to stdout", err)
		}
	}

	ctx.routes()
	ctx.router.Use(mwVersion)
	ctx.router.Use(handlers.CompressHandler)
	ctx.router.Use(handlers.RecoveryHandler())
	r := handlers.LoggingHandler(logfile, ctx.router)
	s := &http.Server{
		Handler:           r,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 20 * time.Second,
	}

	go handleInterrupts(s)

	log.Printf("Starting server on %s", laddr)
	if err = s.Serve(l); err != nil && err != http.ErrServerClosed {
		log.Printf("start server failed; error = %v\n", err)
	}
	<-idleClosed
	log.Printf("%s exiting ...\n", filepath.Base(os.Args[0]))
}

// mwVersion is middleware to add an X-Cashier-Version header to the response.
func mwVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cashier-Version", lib.Version)
		next.ServeHTTP(w, r)
	})
}

func encodeString(s string) string {
	var buffer bytes.Buffer
	chunkSize := 70
	runes := []rune(base64.StdEncoding.EncodeToString([]byte(s)))

	for i := 0; i < len(runes); i += chunkSize {
		end := i + chunkSize
		if end > len(runes) {
			end = len(runes)
		}
		buffer.WriteString(string(runes[i:end]))
		buffer.WriteString("\n")
	}
	buffer.WriteString(".\n")
	return buffer.String()
}

//go:embed static
var static embed.FS

// app contains local context - cookiestore, authsession etc.
type app struct {
	cookiestore   *sessions.CookieStore
	authprovider  auth.Provider
	certstore     store.CertStorer
	keysigner     *signer.KeySigner
	router        *mux.Router
	config        *config.Server
	requireReason bool
}

func (a *app) routes() {
	// login required
	csrfHandler := csrf.Protect([]byte(a.config.CSRFSecret), csrf.Secure(a.config.UseTLS))
	a.router.Methods(http.MethodGet).Path("/").Handler(a.authed(http.HandlerFunc(a.index)))
	a.router.Methods(http.MethodPost).Path("/admin/revoke").Handler(a.authed(csrfHandler(http.HandlerFunc(a.revoke))))
	a.router.Methods(http.MethodGet).Path("/admin/certs").Handler(a.authed(csrfHandler(http.HandlerFunc(a.getAllCerts))))
	a.router.Methods(http.MethodGet).Path("/admin/certs.json").Handler(a.authed(http.HandlerFunc(a.getCertsJSON)))

	// no login required
	a.router.Methods(http.MethodGet).Path("/auth/login").HandlerFunc(a.auth)
	a.router.Methods(http.MethodGet).Path("/auth/callback").HandlerFunc(a.auth)
	a.router.Methods(http.MethodGet).Path("/revoked").HandlerFunc(a.revoked)
	a.router.Methods(http.MethodPost).Path("/sign").HandlerFunc(a.sign)

	a.router.Methods(http.MethodGet).Path("/healthcheck").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, http.StatusText(http.StatusOK))
	})
	a.router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())

	// static files
	a.router.PathPrefix("/static/").Handler(http.FileServer(http.FS(static)))
	// A catch-all handler when path does not exist.
	a.router.NotFoundHandler = a.router.NewRoute().HandlerFunc(a.notFound).GetHandler()
}

func (a *app) notFound(w http.ResponseWriter, r *http.Request) {
	log.Printf("path not found %s\n", r.URL.Path)
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func (a *app) getAuthToken(r *http.Request) *oauth2.Token {
	token := &oauth2.Token{}
	marshalled := a.getSessionVariable(r, "token")
	_ = json.Unmarshal([]byte(marshalled), token)
	return token
}

func (a *app) setAuthToken(w http.ResponseWriter, r *http.Request, token *oauth2.Token) {
	v, _ := json.Marshal(token)
	a.setSessionVariable(w, r, "token", string(v))
}

func (a *app) getSessionVariable(r *http.Request, key string) string {
	session, _ := a.cookiestore.Get(r, "session")
	v, ok := session.Values[key].(string)
	if !ok {
		v = ""
	}
	return v
}

func (a *app) setSessionVariable(w http.ResponseWriter, r *http.Request, key, value string) {
	session, _ := a.cookiestore.Get(r, "session")
	session.Values[key] = value
	_ = session.Save(r, w)
}

func (a *app) authed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := a.getAuthToken(r)
		if !t.Valid() || !a.authprovider.Valid(t) {
			a.setSessionVariable(w, r, "origin_url", r.URL.EscapedPath())
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func signalProc(pid int, sig os.Signal) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		log.Printf("find process %d failed; error = %v\n", err)
		return err
	}
	if err := proc.Signal(sig); err != nil {
		log.Printf("send %v to %d failed; error = %v", err)
		return err
	}
	return nil
}
