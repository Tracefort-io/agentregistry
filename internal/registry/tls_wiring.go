package registry

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// httpClientWithCA returns an HTTP client with the given timeout that, when
// caFile is set, trusts only the PEM certificates in it: the private CA of
// an in-cluster service. setting names the option in errors.
func httpClientWithCA(timeout time.Duration, caFile, setting string) (*http.Client, error) {
	client := &http.Client{Timeout: timeout}
	if caFile == "" {
		return client, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", setting, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s %s holds no PEM certificates", setting, caFile)
	}
	client.Transport = &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	return client, nil
}
