package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

// maxStatusVersions bounds how many versions Status compares with OPA.
const maxStatusVersions = 10

// OPAClient reads the modules an OPA has loaded from its REST API
// (GET /v1/policies).
type OPAClient struct {
	URL   string
	Token string
	HTTP  *http.Client
}

// Modules implements LoadedModules.
func (c *OPAClient) Modules(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.URL, "/")+"/v1/policies", nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read OPA policies: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read OPA policies: %s", resp.Status)
	}
	var out struct {
		Result []struct {
			Raw string `json:"raw"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode OPA policies: %w", err)
	}
	modules := make([]string, 0, len(out.Result))
	for _, m := range out.Result {
		modules = append(modules, m.Raw)
	}
	return modules, nil
}

// PolicyStatus is what OPA has loaded of a policy.
type PolicyStatus struct {
	// Checked is false when no OPA is configured.
	Checked bool `json:"checked"`
	// Loaded is true when every .rego file of LiveRef is loaded in OPA.
	Loaded bool `json:"loaded"`
	// LiveVersion is the newest version whose .rego files OPA has loaded,
	// "head" when OPA matches the branch head but no version does.
	LiveVersion string `json:"liveVersion,omitempty"`
	// HeadLoaded is true when OPA has the branch head's .rego files.
	HeadLoaded bool `json:"headLoaded"`
}

// Status compares the policy's .rego files with the modules OPA has loaded,
// at the branch head and at its latest versions. It compares contents, not
// module ids, since how ids are named depends on what loads OPA (OPAL uses
// file paths).
func (s *Service) Status(ctx context.Context, name string) (PolicyStatus, error) {
	if err := s.authorize(ctx, auth.PermissionActionRead, name); err != nil {
		return PolicyStatus{}, err
	}
	if s.cfg.OPA == nil {
		return PolicyStatus{}, nil
	}
	modules, err := s.cfg.OPA.Modules(ctx)
	if err != nil {
		return PolicyStatus{}, err
	}
	loaded := make(map[string]bool, len(modules))
	for _, m := range modules {
		loaded[m] = true
	}
	repo, _, err := s.cfg.Open(ctx)
	if err != nil {
		return PolicyStatus{}, err
	}
	matches := func(sha string) (bool, error) {
		files, err := repo.ReadFiles(ctx, sha, name)
		if err != nil {
			return false, err
		}
		found := false
		for rel, content := range files {
			if !strings.HasSuffix(rel, ".rego") {
				continue
			}
			found = true
			if !loaded[string(content)] {
				return false, nil
			}
		}
		return found, nil
	}
	head, err := repo.Resolve(ctx, s.cfg.Branch)
	if err != nil {
		return PolicyStatus{}, err
	}
	st := PolicyStatus{Checked: true}
	if st.HeadLoaded, err = matches(head); err != nil {
		return PolicyStatus{}, err
	}
	tags, err := repo.ListTags(ctx, name+"/v")
	if err != nil {
		return PolicyStatus{}, err
	}
	for i, v := range versionTags(name, tags) {
		if i == maxStatusVersions {
			break
		}
		ok, err := matches(v.tag.Commit)
		if err != nil {
			return PolicyStatus{}, err
		}
		if ok {
			st.Loaded, st.LiveVersion = true, "v"+strconv.Itoa(v.n)
			return st, nil
		}
	}
	if st.HeadLoaded {
		st.Loaded, st.LiveVersion = true, "head"
	}
	return st, nil
}
