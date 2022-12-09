package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/tkandal/cashier/lib"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	allRead         = os.FileMode(0644)
	onlyOwner       = os.FileMode(0600)
	reqTimeout      = 30 * time.Second
	applicationJSON = "application/json"
)

var (
	errNeedsReason = errors.New("reason required")
)

// SavePublicFiles installs the public part of the cert and key.
func SavePublicFiles(prefix string, cert *ssh.Certificate, pub ssh.PublicKey) error {
	if prefix == "" {
		return nil
	}
	pubTxt := ssh.MarshalAuthorizedKey(pub)
	certPubTxt := []byte(cert.Type() + " " + base64.StdEncoding.EncodeToString(cert.Marshal()))

	_prefix := filepath.Join(prefix, "id_"+cert.KeyId)

	if err := os.WriteFile(_prefix+".pub", pubTxt, allRead); err != nil {
		return err
	}
	err := os.WriteFile(_prefix+"-cert.pub", certPubTxt, allRead)

	return err
}

// SavePrivateFiles installs the private part of the key.
func SavePrivateFiles(prefix string, cert *ssh.Certificate, key Key) error {
	if prefix == "" {
		return nil
	}
	_prefix := filepath.Join(prefix, "id_"+cert.KeyId)
	pemBlock, err := pemBlockForKey(key)
	if err != nil {
		return err
	}
	err = os.WriteFile(_prefix, pem.EncodeToMemory(pemBlock), onlyOwner)
	return err
}

// InstallCert adds the private key and signed certificate to the ssh agent.
func InstallCert(a agent.Agent, cert *ssh.Certificate, key Key) error {
	t := time.Unix(int64(cert.ValidBefore), 0)
	lifetime := t.Sub(time.Now()).Seconds()
	comment := fmt.Sprintf("%s [Expires %s]", cert.KeyId, t)
	pubcert := agent.AddedKey{
		PrivateKey:   key,
		Certificate:  cert,
		Comment:      comment,
		LifetimeSecs: uint32(lifetime),
	}
	if err := a.Add(pubcert); err != nil {
		return errors.Wrap(err, "unable to add cert to ssh agent")
	}
	privkey := agent.AddedKey{
		PrivateKey:   key,
		Comment:      comment,
		LifetimeSecs: uint32(lifetime),
	}
	if err := a.Add(privkey); err != nil {
		return errors.Wrap(err, "unable to add private key to ssh agent")
	}
	return nil
}

// send the signing request to the CA.
func send(sr *lib.SignRequest, token, ca string, ValidateTLSCertificate bool) (*lib.SignResponse, error) {
	s, err := json.Marshal(sr)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create sign request")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !ValidateTLSCertificate},
		},
		Timeout: reqTimeout,
	}
	u, err := url.Parse(ca)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse CA url")
	}
	if strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	u.Path = fmt.Sprintf("%s/sign", u.Path)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(reqTimeout))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(s))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", applicationJSON+";charset=utf-8")
	req.Header.Add("Accept", applicationJSON)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	signResponse := &lib.SignResponse{}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden && strings.HasPrefix(resp.Header.Get("X-Need-Reason"), "required") {
			return signResponse, errNeedsReason
		}
		return signResponse, fmt.Errorf("bad response from server: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(signResponse); err != nil {
		return nil, errors.Wrap(err, "unable to decode server response")
	}
	return signResponse, nil
}

func promptForReason() (message string) {
	fmt.Print("Enter message: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		message = scanner.Text()
	}
	return message
}

// Sign sends the public key to the CA to be signed.
func Sign(pub ssh.PublicKey, token string, conf *Config) (*ssh.Certificate, error) {
	var err error
	validity, err := time.ParseDuration(conf.Validity)
	if err != nil {
		return nil, err
	}
	s := &lib.SignRequest{
		Key:        string(lib.GetPublicKey(pub)),
		ValidUntil: time.Now().Add(validity),
		Version:    lib.Version,
	}
	resp := &lib.SignResponse{}
	for {
		resp, err = send(s, token, conf.CA, conf.ValidateTLSCertificate)
		if err == nil {
			break
		}
		if err != nil && err == errNeedsReason {
			s.Message = promptForReason()
			continue
		} else if err != nil {
			return nil, errors.Wrap(err, "error sending request to CA")
		}
	}
	if strings.ToLower(resp.Status) != "ok" {
		return nil, fmt.Errorf("bad response from CA: %s", resp.Response)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Response))
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse response")
	}
	cert, ok := k.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("did not receive a valid certificate from server")
	}
	return cert, nil
}
