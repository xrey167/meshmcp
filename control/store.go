package control

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FilePolicyStore stores named policies as <name>.yaml files in a directory.
type FilePolicyStore struct {
	Dir string
}

// NewFilePolicyStore ensures dir exists.
func NewFilePolicyStore(dir string) (*FilePolicyStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &FilePolicyStore{Dir: dir}, nil
}

func (s *FilePolicyStore) path(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\:`) {
		return "", fmt.Errorf("invalid policy name %q", name)
	}
	return filepath.Join(s.Dir, name+".yaml"), nil
}

func (s *FilePolicyStore) Get(name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (s *FilePolicyStore) Put(name string, raw []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o644)
}

func (s *FilePolicyStore) List() ([]string, error) {
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	sort.Strings(names)
	return names, nil
}

// StaticEnroll returns an EnrollFunc that hands out a fixed management URL and
// setup key. This is the MVP backend; swap it for one that mints a scoped,
// short-lived NetBird setup key per node via the management API. registryDir
// and controlNode are echoed back so a node can centralize its state.
func StaticEnroll(managementURL, setupKey, registryDir, controlNode string) EnrollFunc {
	return func(req EnrollRequest) (EnrollResponse, error) {
		if setupKey == "" {
			return EnrollResponse{}, fmt.Errorf("control plane has no setup key configured")
		}
		return EnrollResponse{
			ManagementURL: managementURL,
			SetupKey:      setupKey,
			Registry:      registryDir,
			ControlNode:   controlNode,
		}, nil
	}
}
