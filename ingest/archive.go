package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/google/uuid"
)

type archiveFile struct {
	Name  string `json:"name"`
	Hash  string `json:"sha256"`
	Limit int64  `json:"-"`
}

func openProcessed(path, incoming, published string, input, output *os.Root) (*os.Root, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if overlaps(path, incoming) || overlaps(path, published) {
		return nil, fmt.Errorf("processed, incoming, and published storage must be separate directories")
	}
	ancestor := path
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(ancestor)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			if overlaps(resolved, incoming) || overlaps(resolved, published) {
				return nil, fmt.Errorf("processed, incoming, and published storage must be separate directories")
			}
			break
		}
		if !os.IsNotExist(err) || filepath.Dir(ancestor) == ancestor {
			return nil, err
		}
		suffix = append(suffix, filepath.Base(ancestor))
		ancestor = filepath.Dir(ancestor)
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return nil, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if overlaps(path, incoming) || overlaps(path, published) {
		return nil, fmt.Errorf("processed, incoming, and published storage must be separate directories")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	for _, other := range []*os.Root{input, output} {
		otherInfo, err := other.Stat(".")
		if err != nil || os.SameFile(info, otherInfo) {
			root.Close()
			return nil, fmt.Errorf("processed storage is unavailable or aliases incoming/published storage")
		}
	}
	return root, nil
}

func openArchiveSource(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("archive source %s must be a regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		file.Close()
		return nil, fmt.Errorf("archive source %s changed while opening", name)
	}
	return file, nil
}

func copyArchiveFile(ctx context.Context, source, target *os.Root, spec archiveFile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	input, err := openArchiveSource(source, spec.Name)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := target.OpenFile(spec.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	digest := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, digest), io.LimitReader(input, spec.Limit+1))
	if err == nil && (count > spec.Limit || hex.EncodeToString(digest.Sum(nil)) != spec.Hash) {
		err = fmt.Errorf("%s changed after publication; originals preserved", spec.Name)
	}
	if err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	return errors.Join(err, closeErr, ctx.Err())
}

func archivePackage(ctx context.Context, input, processed *os.Root, result Result) (archived, recovery string, archiveErr error) {
	if result.Status != "imported" && result.Status != "unchanged" || len(result.sourceHashes) == 0 {
		return "", "", fmt.Errorf("only successfully published packages can be archived")
	}
	base := strings.TrimSuffix(result.File, filepath.Ext(result.File))
	var files []archiveFile
	for _, name := range []string{result.File, base + ".sigzip", base + ".publisher.json", base + ".sandbox.json"} {
		limit := int64(sandbox.MaxReportSize)
		if name == result.File || strings.HasSuffix(name, ".sigzip") {
			limit = storage.MaxPackageSize
		}
		digest, required := result.sourceHashes[name]
		if !required {
			data, err := read(input, name, limit)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return "", "", err
			}
			digest = hash(data)
		}
		files = append(files, archiveFile{Name: name, Hash: digest, Limit: limit})
	}
	id := uuid.NewString()
	holding := ".archive-" + id
	partial := ".partial-" + id
	final := result.SHA256 + "-" + id
	if err := processed.Mkdir(partial, 0o750); err != nil {
		return "", "", err
	}
	target, err := processed.OpenRoot(partial)
	if err != nil {
		return "", "", err
	}
	defer target.Close()
	if err := input.Mkdir(holding, 0o700); err != nil {
		return "", "", err
	}
	source, err := input.OpenRoot(holding)
	if err != nil {
		return "", holding, err
	}
	defer source.Close()
	journal, err := json.Marshal(struct {
		Files       []archiveFile `json:"files"`
		Result      Result        `json:"result"`
		Destination string        `json:"destination"`
	}{files, result, final})
	if err != nil {
		return "", holding, err
	}
	if err := storage.WritePrivateFile(source, ".archive-state.json", journal); err != nil {
		return "", holding, err
	}
	var moved []archiveFile
	committed := false
	defer func() {
		if committed || archiveErr == nil {
			return
		}
		for _, file := range moved {
			staged := filepath.Join(holding, file.Name)
			if err := input.Link(staged, file.Name); err != nil {
				recovery = holding
				archiveErr = errors.Join(archiveErr, fmt.Errorf("restore %s: %w; original preserved in %s", file.Name, err, holding))
				continue
			}
			if err := source.Remove(file.Name); err != nil {
				recovery = holding
				archiveErr = errors.Join(archiveErr, err)
			}
		}
		if recovery == "" {
			source.Remove(".archive-state.json")
			source.Close()
			input.Remove(holding)
		}
	}()
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		if err := input.Rename(file.Name, filepath.Join(holding, file.Name)); err != nil {
			return "", "", err
		}
		moved = append(moved, file)
		if err := copyArchiveFile(ctx, source, target, file); err != nil {
			return "", "", err
		}
	}
	if err := storage.WritePrivateFile(target, ".archive-state.json", journal); err != nil {
		return "", "", err
	}
	if err := target.Close(); err != nil {
		return "", "", err
	}
	if err := processed.Rename(partial, final); err != nil {
		return "", "", err
	}
	committed = true
	for _, file := range moved {
		if err := source.Remove(file.Name); err != nil {
			return final, holding, err
		}
	}
	if err := source.Remove(".archive-state.json"); err != nil {
		return final, holding, err
	}
	if err := source.Close(); err != nil {
		return final, holding, err
	}
	if err := input.Remove(holding); err != nil {
		return final, holding, err
	}
	return final, "", nil
}
