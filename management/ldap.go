package management

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type User struct {
	Name string `json:"name"`
	Role string `json:"role"`
	DN   string `json:"-"`
}

type Authenticator interface {
	Authenticate(context.Context, string, string) (User, error)
	Authorize(context.Context, User) (User, error)
}

type directory struct {
	config LDAPConfig
	tls    *tls.Config
}

func newDirectory(config LDAPConfig) (*directory, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if config.CAFile != "" {
		pem, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("LDAP CA file contains no certificates")
		}
	}
	if _, err := readPassword(config.BindPasswordFile); err != nil {
		return nil, err
	}
	return &directory{config: config, tls: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: endpoint.Hostname()}}, nil
}

func readPassword(filename string) (string, error) {
	data, err := readBoundedFile(filename, 4096)
	if err != nil {
		return "", err
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", fmt.Errorf("LDAP bind password is empty")
	}
	return password, nil
}

func (d *directory) connect(ctx context.Context) (*ldap.Conn, func(), error) {
	endpoint, err := url.Parse(d.config.URL)
	if err != nil {
		return nil, nil, err
	}
	port := endpoint.Port()
	if port == "" {
		if endpoint.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	connection, err := (&net.Dialer{Timeout: d.config.Timeout}).DialContext(ctx, "tcp", net.JoinHostPort(endpoint.Hostname(), port))
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(d.config.Timeout)
	if current, ok := ctx.Deadline(); ok && current.Before(deadline) {
		deadline = current
	}
	if err := connection.SetDeadline(deadline); err != nil {
		connection.Close()
		return nil, nil, err
	}
	if endpoint.Scheme == "ldaps" {
		secure := tls.Client(connection, d.tls.Clone())
		if err := secure.HandshakeContext(ctx); err != nil {
			connection.Close()
			return nil, nil, err
		}
		connection = secure
	}
	client := ldap.NewConn(connection, endpoint.Scheme == "ldaps")
	client.SetTimeout(d.config.Timeout)
	client.Start()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	closeConnection := func() { stop(); client.Close() }
	if endpoint.Scheme == "ldap" {
		if err := client.StartTLS(d.tls.Clone()); err != nil {
			closeConnection()
			return nil, nil, err
		}
	}
	return client, closeConnection, nil
}

func (d *directory) lookup(client *ldap.Conn, username string) (*ldap.Entry, error) {
	password, err := readPassword(d.config.BindPasswordFile)
	if err != nil {
		return nil, err
	}
	if err := client.Bind(d.config.BindDN, password); err != nil {
		return nil, err
	}
	filter := "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(objectCategory=person)(" + d.config.UsernameAttribute + "=" + ldap.EscapeFilter(username) + "))"
	result, err := client.Search(ldap.NewSearchRequest(d.config.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, []string{d.config.UsernameAttribute}, nil))
	if err != nil || len(result.Entries) != 1 {
		return nil, fmt.Errorf("AD user lookup failed")
	}
	entry := result.Entries[0]
	base, err := ldap.ParseDN(d.config.UserBaseDN)
	if err != nil {
		return nil, err
	}
	dn, err := ldap.ParseDN(entry.DN)
	if err != nil || !base.AncestorOfFold(dn) {
		return nil, fmt.Errorf("AD user is outside the configured search base")
	}
	if !strings.EqualFold(entry.GetAttributeValue(d.config.UsernameAttribute), username) {
		return nil, fmt.Errorf("AD user identity does not match the request")
	}
	return entry, nil
}

func (d *directory) role(client *ldap.Conn, entry *ldap.Entry) (User, error) {
	for _, mapping := range []struct {
		role   string
		groups []string
	}{{"admin", d.config.AdminGroups}, {"reader", d.config.ReaderGroups}} {
		for _, group := range mapping.groups {
			filter := "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(group) + "))"
			result, err := client.Search(ldap.NewSearchRequest(entry.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, filter, []string{d.config.UsernameAttribute}, nil))
			if err != nil {
				return User{}, err
			}
			if len(result.Entries) == 1 && strings.EqualFold(result.Entries[0].DN, entry.DN) {
				return User{Name: entry.GetAttributeValue(d.config.UsernameAttribute), DN: entry.DN, Role: mapping.role}, nil
			}
		}
	}
	return User{}, fmt.Errorf("AD user has no authorized group")
}

func (d *directory) Authenticate(ctx context.Context, username, password string) (User, error) {
	if strings.TrimSpace(username) == "" || len(username) > 256 || len(password) == 0 || len(password) > 4096 {
		return User{}, fmt.Errorf("invalid credentials")
	}
	client, closeConnection, err := d.connect(ctx)
	if err != nil {
		return User{}, err
	}
	defer closeConnection()
	entry, err := d.lookup(client, username)
	if err != nil {
		return User{}, err
	}
	if err := client.Bind(entry.DN, password); err != nil {
		return User{}, err
	}
	bindPassword, err := readPassword(d.config.BindPasswordFile)
	if err != nil {
		return User{}, err
	}
	if err := client.Bind(d.config.BindDN, bindPassword); err != nil {
		return User{}, err
	}
	return d.role(client, entry)
}

func (d *directory) Authorize(ctx context.Context, user User) (User, error) {
	client, closeConnection, err := d.connect(ctx)
	if err != nil {
		return User{}, err
	}
	defer closeConnection()
	entry, err := d.lookup(client, user.Name)
	if err != nil || !strings.EqualFold(entry.DN, user.DN) {
		return User{}, fmt.Errorf("AD identity is no longer authorized")
	}
	return d.role(client, entry)
}
