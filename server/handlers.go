package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/pkg/errors"
	"github.com/tkandal/cashier/lib"
	"github.com/tkandal/cashier/server/store"
	"github.com/tkandal/cashier/server/templates"
	"golang.org/x/oauth2"
)

func (a *app) sign(w http.ResponseWriter, r *http.Request) {
	var t string
	if ah := r.Header.Get("Authorization"); ah != "" {
		if len(ah) > 6 && strings.ToUpper(ah[0:7]) == "BEARER " {
			t = ah[7:]
		}
	}

	token := &oauth2.Token{
		AccessToken: t,
	}
	if !a.authprovider.Valid(token) {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Sign the pubkey and issue the cert.
	req := &lib.SignRequest{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		_, _ = fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if a.requireReason && req.Message == "" {
		w.Header().Add("X-Need-Reason", "required")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	username := a.authprovider.Username(token)
	_ = a.authprovider.Revoke(token) // We don't need this anymore.
	cert, err := a.keysigner.SignUserKey(req, username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "Error signing key")
		return
	}

	rec := store.MakeRecord(cert)
	rec.Message = req.Message
	if err := a.certstore.SetRecord(rec); err != nil {
		log.Printf("Error recording cert: %v", err)
	}
	if err := json.NewEncoder(w).Encode(&lib.SignResponse{
		Status:   "ok",
		Response: string(lib.GetPublicKey(cert)),
	}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, "Error signing key")
		return
	}
}

func (a *app) auth(w http.ResponseWriter, r *http.Request) {
	switch r.URL.EscapedPath() {
	case "/auth/login":
		buf := make([]byte, stateLen)
		_, _ = io.ReadFull(rand.Reader, buf)
		state := hex.EncodeToString(buf)
		a.setSessionVariable(w, r, "state", state)
		http.Redirect(w, r, a.authprovider.StartSession(state, w, r), http.StatusSeeOther)
	case "/auth/callback":
		state := a.getSessionVariable(r, "state")
		if r.FormValue("state") != state {
			log.Printf("Not authorized on /auth/callback")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			break
		}
		originURL := a.getSessionVariable(r, "origin_url")
		if originURL == "" {
			originURL = "/"
		}
		code := r.FormValue("code")
		token, err := a.authprovider.Exchange(code, r)
		if err != nil {
			log.Printf("Error on /auth/callback: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			_, _ = w.Write([]byte(err.Error()))
			break
		}
		log.Printf("Token found on /auth/callback, redirecting to %s", originURL)
		a.setAuthToken(w, r, token)

		// if we don't check the token here, it gets into an auth loop
		if !a.authprovider.Valid(token) {
			log.Printf("Not authorized")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			break
		}
		http.Redirect(w, r, originURL, http.StatusFound)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	tok := a.getAuthToken(r)
	page := struct {
		Token string
	}{tok.AccessToken}
	page.Token = encodeString(page.Token)
	tmpl := template.Must(template.New("token.html").Parse(templates.Token))
	_ = tmpl.Execute(w, page)
}

func (a *app) revoked(w http.ResponseWriter, r *http.Request) {
	revoked, err := a.certstore.GetRevoked()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, errors.Wrap(err, "error retrieving revoked certs").Error())
		return
	}
	rl, err := a.keysigner.GenerateRevocationList(revoked)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, errors.Wrap(err, "unable to generate KRL").Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(rl)
}

func (a *app) getAllCerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	tmpl := template.Must(template.New("certs.html").Parse(templates.Certs))
	_ = tmpl.Execute(w, map[string]interface{}{
		csrf.TemplateTag: csrf.TemplateField(r),
	})
}

func (a *app) getCertsJSON(w http.ResponseWriter, r *http.Request) {
	includeExpired, _ := strconv.ParseBool(r.URL.Query().Get("all"))
	certs, err := a.certstore.List(includeExpired)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(certs); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (a *app) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("parse form failed; error = %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("unable to parse form"))
		return
	}
	if err := a.certstore.Revoke(r.Form["cert_id"]); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Unable to revoke certs"))
	} else {
		http.Redirect(w, r, "/admin/certs", http.StatusSeeOther)
	}
}
