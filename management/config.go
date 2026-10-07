package management

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Address       string          `yaml:"address"`
	PublicURL     string          `yaml:"publicURL"`
	ExtensionsDir string          `yaml:"extensionsDir"`
	IncomingDir   string          `yaml:"incomingDir"`
	AuditFile     string          `yaml:"auditFile"`
	LDAP          LDAPConfig      `yaml:"ldap"`
	Session       SessionConfig   `yaml:"session"`
	Publisher     PublisherConfig `yaml:"publisher"`
}

type LDAPConfig struct {
	URL               string        `yaml:"url"`
	CAFile            string        `yaml:"caFile"`
	BindDN            string        `yaml:"bindDN"`
	BindPasswordFile  string        `yaml:"bindPasswordFile"`
	UserBaseDN        string        `yaml:"userBaseDN"`
	UsernameAttribute string        `yaml:"usernameAttribute"`
	ReaderGroups      []string      `yaml:"readerGroups"`
	AdminGroups       []string      `yaml:"adminGroups"`
	Timeout           time.Duration `yaml:"timeout"`
}

type SessionConfig struct {
	Lifetime        time.Duration `yaml:"lifetime"`
	IdleTimeout     time.Duration `yaml:"idleTimeout"`
	RecheckInterval time.Duration `yaml:"recheckInterval"`
	MaxSessions     int           `yaml:"maxSessions"`
}

type PublisherConfig struct {
	Mode       string        `yaml:"mode"`
	PolicyFile string        `yaml:"policyFile"`
	MaxAge     time.Duration `yaml:"maxAge"`
}

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, err
	}
	if len(data) > 65536 {
		return nil, fmt.Errorf("management YAML exceeds 64 KiB")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	if err := validateYAML(&node); err != nil {
		return nil, err
	}
	config := &Config{Address: "127.0.0.1:8081", LDAP: LDAPConfig{UsernameAttribute: "sAMAccountName", Timeout: 10 * time.Second}, Session: SessionConfig{Lifetime: time.Hour, IdleTimeout: 15 * time.Minute, RecheckInterval: time.Minute, MaxSessions: 1000}, Publisher: PublisherConfig{Mode: "verified", MaxAge: 168 * time.Hour}}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("one YAML document is required")
	}
	base, err := filepath.Abs(filepath.Dir(filename))
	if err != nil {
		return nil, err
	}
	for _, path := range []*string{&config.ExtensionsDir, &config.IncomingDir, &config.AuditFile, &config.LDAP.CAFile, &config.LDAP.BindPasswordFile, &config.Publisher.PolicyFile} {
		if *path != "" && !filepath.IsAbs(*path) {
			*path = filepath.Join(base, *path)
		}
	}
	return config, config.Validate()
}

func validateYAML(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("YAML aliases and anchors are not supported")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || seen[key.Value] || key.Value == "<<" {
				return fmt.Errorf("duplicate or invalid YAML key")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) Validate() error {
	public, err := url.Parse(c.PublicURL)
	if err != nil || public.Scheme != "https" || public.Host == "" || public.User != nil || public.RawQuery != "" || public.Fragment != "" || public.Opaque != "" || (public.Path != "" && public.Path != "/") {
		return fmt.Errorf("publicURL must be an HTTPS origin without a path")
	}
	c.PublicURL = "https://" + public.Host
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return fmt.Errorf("invalid management listen address: %w", err)
	}
	endpoint, err := url.Parse(c.LDAP.URL)
	if err != nil || (endpoint.Scheme != "ldaps" && endpoint.Scheme != "ldap") || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" {
		return fmt.Errorf("ldap.url must use LDAPS or LDAP with mandatory StartTLS")
	}
	if c.LDAP.UsernameAttribute != "sAMAccountName" && c.LDAP.UsernameAttribute != "userPrincipalName" {
		return fmt.Errorf("usernameAttribute must be sAMAccountName or userPrincipalName")
	}
	if c.LDAP.BindPasswordFile == "" || c.LDAP.Timeout < time.Second || c.LDAP.Timeout > 30*time.Second {
		return fmt.Errorf("LDAP password file and a timeout between 1s and 30s are required")
	}
	for _, dn := range append([]string{c.LDAP.BindDN, c.LDAP.UserBaseDN}, append(c.LDAP.ReaderGroups, c.LDAP.AdminGroups...)...) {
		if dn == "" || len(dn) > 2048 {
			return fmt.Errorf("nonempty LDAP distinguished names are required")
		}
		if _, err := ldap.ParseDN(dn); err != nil {
			return fmt.Errorf("invalid LDAP distinguished name: %w", err)
		}
	}
	if len(c.LDAP.ReaderGroups)+len(c.LDAP.AdminGroups) == 0 || len(c.LDAP.ReaderGroups)+len(c.LDAP.AdminGroups) > 64 {
		return fmt.Errorf("configure between 1 and 64 authorized AD groups")
	}
	if c.Session.Lifetime < time.Minute || c.Session.Lifetime > 8*time.Hour || c.Session.IdleTimeout < time.Minute || c.Session.IdleTimeout > c.Session.Lifetime || c.Session.RecheckInterval < time.Second || c.Session.RecheckInterval > time.Minute || c.Session.MaxSessions < 1 || c.Session.MaxSessions > 10000 {
		return fmt.Errorf("invalid management session limits")
	}
	if c.ExtensionsDir == "" || c.IncomingDir == "" || c.AuditFile == "" {
		return fmt.Errorf("extensionsDir, incomingDir and auditFile are required")
	}
	if c.Publisher.Mode != "verified" && c.Publisher.Mode != "allowlist" && c.Publisher.Mode != "any" {
		return fmt.Errorf("invalid publisher mode")
	}
	if c.Publisher.Mode != "any" && (c.Publisher.PolicyFile == "" || c.Publisher.MaxAge <= 0) {
		return fmt.Errorf("publisher policyFile and maxAge are required")
	}
	for _, dir := range []string{c.ExtensionsDir, c.IncomingDir, filepath.Dir(c.AuditFile)} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("management directory is unavailable: %s", dir)
		}
	}
	for _, pair := range [][2]string{{c.ExtensionsDir, c.IncomingDir}, {c.ExtensionsDir, filepath.Dir(c.AuditFile)}, {c.IncomingDir, filepath.Dir(c.AuditFile)}} {
		if overlap(pair[0], pair[1]) {
			return fmt.Errorf("published, incoming and audit directories must be separate")
		}
	}
	for _, file := range []string{c.LDAP.BindPasswordFile, c.LDAP.CAFile, c.Publisher.PolicyFile} {
		if file != "" && (overlap(c.IncomingDir, file) || overlap(c.ExtensionsDir, file)) {
			return fmt.Errorf("trusted configuration and credentials must be outside package storage")
		}
	}
	return nil
}

func overlap(a, b string) bool {
	resolve := func(value string) string {
		value, _ = filepath.Abs(value)
		if real, err := filepath.EvalSymlinks(value); err == nil {
			value = real
		}
		return strings.ToLower(filepath.Clean(value))
	}
	a, b = resolve(a), resolve(b)
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}
