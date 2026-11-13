package approvals

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxCallbackBody = 64 << 10
	// callbackTolerance bounds how old (or early) a signed callback may be,
	// so a captured one cannot be replayed later.
	callbackTolerance = 5 * time.Minute
)

// CallbackHandler receives the access request service's notices that a
// request ended (X-AuthZEN-Signature: t=<unix>,v1=<hex HMAC-SHA256 of
// "<t>.<body>">). The notice only names the task; the registry reads the
// outcome from the service itself, so a forged or replayed notice can at
// worst make it check early. Delivery is at least once; processing is
// idempotent.
func (s *Service) CallbackHandler(secret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxCallbackBody+1))
		if err != nil || len(body) > maxCallbackBody {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		if err := verifySignature(secret, r.Header.Get("X-AuthZEN-Signature"), body, s.now()); err != nil {
			logger.Warn("access request callback refused", "error", err, "remote", r.RemoteAddr)
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		var notice struct {
			Task struct {
				ID string `json:"id"`
			} `json:"task"`
		}
		if json.Unmarshal(body, &notice) != nil || notice.Task.ID == "" {
			http.Error(w, "invalid notice", http.StatusBadRequest)
			return
		}
		go s.Process(context.WithoutCancel(r.Context()), notice.Task.ID)
		w.WriteHeader(http.StatusNoContent)
	})
}

func verifySignature(secret []byte, header string, body []byte, now time.Time) error {
	if len(secret) == 0 {
		return errors.New("no callback secret configured")
	}
	var ts, sig string
	for part := range strings.SplitSeq(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return errors.New("malformed signature header")
	}
	if d := now.Sub(time.Unix(unix, 0)); d > callbackTolerance || d < -callbackTolerance {
		return errors.New("signature timestamp out of range")
	}
	want, err := hex.DecodeString(sig)
	if err != nil {
		return errors.New("malformed signature")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("signature mismatch")
	}
	return nil
}
