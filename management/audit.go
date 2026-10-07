package management

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coder/code-marketplace/filelock"
	"github.com/google/uuid"
)

type AuditEvent struct {
	Time          time.Time `json:"time"`
	ID            string    `json:"id"`
	Actor         string    `json:"actor"`
	Role          string    `json:"role,omitempty"`
	Action        string    `json:"action"`
	Target        string    `json:"target,omitempty"`
	Result        string    `json:"result"`
	RemoteAddress string    `json:"remoteAddress"`
}

func (s *Server) audit(r *http.Request, user User, action, target, result string) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if len(user.Name) > 256 {
		user.Name = user.Name[:256]
	}
	data, err := json.Marshal(AuditEvent{Time: time.Now().UTC(), ID: uuid.NewString(), Actor: user.Name, Role: user.Role, Action: action, Target: target, Result: result, RemoteAddress: r.RemoteAddr})
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(s.config.AuditFile))
	if err != nil {
		return err
	}
	defer root.Close()
	release, err := filelock.Acquire(root, ".admin-audit.lock")
	if err != nil {
		return err
	}
	defer release()
	file, err := root.OpenFile(filepath.Base(s.config.AuditFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("audit log must be a regular file")
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func readRequest(r *http.Request) ([]byte, error) {
	return io.ReadAll(r.Body)
}

func readBoundedFile(filename string, limit int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("configuration must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("configuration exceeds its size limit")
	}
	return data, nil
}
