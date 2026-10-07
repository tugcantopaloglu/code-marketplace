package management

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
)

type testDirectory struct {
	listener    net.Listener
	certificate tls.Certificate
	mu          sync.Mutex
	filters     []string
	binds       []string
	denied      bool
	startTLS    bool
	wg          sync.WaitGroup
}

func ldapMessage(id int64, operation *ber.Packet) []byte {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	packet.AppendChild(operation)
	return packet.Bytes()
}

func ldapResult(tag ber.Tag, code int64) *ber.Packet {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	return packet
}

func ldapEntry() *ber.Packet {
	packet := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "CN=Alice,OU=Users,DC=example", ""))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "sAMAccountName", ""))
	values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
	values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "alice", ""))
	attribute.AppendChild(values)
	attributes.AppendChild(attribute)
	packet.AppendChild(attributes)
	return packet
}

func (d *testDirectory) serve(connection net.Conn) {
	defer d.wg.Done()
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	secure := !d.startTLS
	if secure {
		encrypted := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{d.certificate}, MinVersion: tls.VersionTLS12})
		if encrypted.Handshake() != nil {
			return
		}
		connection = encrypted
	}
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		id := packet.Children[0].Value.(int64)
		operation := packet.Children[1]
		if !secure {
			if operation.Tag != 23 {
				return
			}
			connection.Write(ldapMessage(id, ldapResult(24, 0)))
			encrypted := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{d.certificate}, MinVersion: tls.VersionTLS12})
			if encrypted.Handshake() != nil {
				return
			}
			connection = encrypted
			secure = true
			continue
		}
		switch operation.Tag {
		case 0:
			name := operation.Children[1].Value.(string)
			password := operation.Children[2].Data.String()
			d.mu.Lock()
			d.binds = append(d.binds, name)
			d.mu.Unlock()
			code := int64(49)
			if (name == "CN=service,DC=example" && password == "test-bind-password") || (name == "CN=Alice,OU=Users,DC=example" && password == "test-user-password") {
				code = 0
			}
			connection.Write(ldapMessage(id, ldapResult(1, code)))
		case 3:
			filter, err := ldap.DecompileFilter(operation.Children[6])
			if err != nil {
				return
			}
			d.mu.Lock()
			d.filters = append(d.filters, filter)
			denied := d.denied
			d.mu.Unlock()
			if !denied || !strings.Contains(filter, "memberOf") {
				connection.Write(ldapMessage(id, ldapEntry()))
			}
			connection.Write(ldapMessage(id, ldapResult(5, 0)))
		default:
			return
		}
	}
}

func runDirectory(t *testing.T, startTLS bool) (*testDirectory, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test AD"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	d := &testDirectory{listener: listener, certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, startTLS: startTLS}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			d.wg.Add(1)
			go d.serve(connection)
		}
	}()
	t.Cleanup(func() { listener.Close(); d.wg.Wait() })
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return d, path
}

func TestLDAPSTrustAndGroupRevalidation(t *testing.T) {
	for _, startTLS := range []bool{false, true} {
		d, ca := runDirectory(t, startTLS)
		config := testConfig(t).LDAP
		config.CAFile = ca
		scheme := "ldaps"
		if startTLS {
			scheme = "ldap"
		}
		config.URL = scheme + "://" + d.listener.Addr().String()
		directory, err := newDirectory(config)
		require.NoError(t, err)
		user, err := directory.Authenticate(context.Background(), "alice", "test-user-password")
		require.NoError(t, err)
		require.Equal(t, "admin", user.Role)
		d.mu.Lock()
		binds := append([]string{}, d.binds...)
		filters := append([]string{}, d.filters...)
		d.denied = true
		d.mu.Unlock()
		require.Equal(t, []string{config.BindDN, user.DN, config.BindDN}, binds)
		require.Contains(t, strings.Join(filters, " "), "memberOf:1.2.840.113556.1.4.1941:=")
		_, err = directory.Authorize(context.Background(), user)
		require.Error(t, err)
		_, err = directory.Authenticate(context.Background(), "alice", "wrong")
		require.Error(t, err)
		_, err = directory.Authenticate(context.Background(), "alice", "")
		require.Error(t, err)
		config.CAFile = ""
		untrusted, err := newDirectory(config)
		require.NoError(t, err)
		d.mu.Lock()
		before := len(d.binds)
		d.mu.Unlock()
		_, err = untrusted.Authenticate(context.Background(), "alice", "test-user-password")
		require.Error(t, err)
		d.mu.Lock()
		after := len(d.binds)
		d.mu.Unlock()
		require.Equal(t, before, after)
	}
}

func TestLDAPEscapesUserFilter(t *testing.T) {
	d, ca := runDirectory(t, false)
	config := testConfig(t).LDAP
	config.CAFile = ca
	config.URL = "ldaps://" + d.listener.Addr().String()
	directory, err := newDirectory(config)
	require.NoError(t, err)
	_, err = directory.Authenticate(context.Background(), "alice*)(sAMAccountName=*)", "test-user-password")
	require.Error(t, err)
	d.mu.Lock()
	filter := d.filters[0]
	d.mu.Unlock()
	require.Contains(t, filter, `alice\2a\29\28sAMAccountName=\2a\29`)
}
