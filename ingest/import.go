package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/extensionsign"
	"github.com/coder/code-marketplace/filelock"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
)

const ReceiptName = ".import-receipt.json"

type Receipt struct {
	SchemaVersion int              `json:"schemaVersion"`
	SHA256        string           `json:"sha256"`
	SignatureHash string           `json:"signatureSha256"`
	ImportedAt    time.Time        `json:"importedAt"`
	Approval      sandbox.Approval `json:"sandbox"`
}

type Result struct {
	File                string   `json:"file"`
	Extension           string   `json:"extension,omitempty"`
	SHA256              string   `json:"sha256,omitempty"`
	Status              string   `json:"status"`
	Reason              string   `json:"reason,omitempty"`
	Dependencies        []string `json:"dependencies,omitempty"`
	MissingDependencies []string `json:"missingDependencies,omitempty"`
}

type Summary struct {
	CompletedAt time.Time `json:"completedAt"`
	Results     []Result  `json:"results"`
}

type Options struct {
	Incoming string
	Storage  string
	Policy   *sandbox.Policy
	Logger   slog.Logger
}

func Run(ctx context.Context, options Options) (*Summary, error) {
	if options.Policy == nil || len(options.Policy.Keys) == 0 || options.Policy.MaxAge <= 0 {
		return nil, fmt.Errorf("trusted sandbox approval is mandatory for scheduled imports")
	}
	if err := os.MkdirAll(options.Storage, 0o755); err != nil {
		return nil, err
	}
	incoming, err := filepath.EvalSymlinks(options.Incoming)
	if err != nil {
		return nil, err
	}
	destination, err := filepath.EvalSymlinks(options.Storage)
	if err != nil {
		return nil, err
	}
	incoming, err = filepath.Abs(incoming)
	if err != nil {
		return nil, err
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return nil, err
	}
	if overlaps(incoming, destination) {
		return nil, fmt.Errorf("incoming and published storage must be separate directories")
	}
	input, err := os.OpenRoot(incoming)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	output, err := os.OpenRoot(destination)
	if err != nil {
		return nil, err
	}
	defer output.Close()
	inputInfo, err := input.Stat(".")
	if err != nil {
		return nil, err
	}
	outputInfo, err := output.Stat(".")
	if err != nil {
		return nil, err
	}
	if os.SameFile(inputInfo, outputInfo) {
		return nil, fmt.Errorf("incoming and published storage must not be aliases of the same directory")
	}
	release, err := filelock.Acquire(output, ".ingest.lock")
	if err != nil {
		return nil, fmt.Errorf("another import may be running; inspect .ingest.lock: %w", err)
	}
	defer release()
	store, err := storage.NewStorage(ctx, &storage.Options{ExtDir: destination, Logger: options.Logger, Immutable: true})
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(incoming)
	if err != nil {
		return nil, err
	}
	summary := &Summary{Results: []Result{}}
	var failed bool
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".vsix") {
			continue
		}
		result := importPackage(ctx, input, output, store, options.Policy, entry.Name())
		summary.Results = append(summary.Results, result)
		failed = failed || result.Status == "failed" || result.Status == "conflict"
	}
	available := map[string]bool{}
	if err := store.WalkExtensions(ctx, func(manifest *storage.VSIXManifest, _ []storage.Version) error {
		available[strings.ToLower(storage.ExtensionIDWithoutVersion(manifest.Metadata.Identity.Publisher, manifest.Metadata.Identity.ID))] = true
		return nil
	}); err != nil {
		return summary, err
	}
	for i := range summary.Results {
		result := &summary.Results[i]
		if result.Status != "imported" && result.Status != "unchanged" {
			continue
		}
		for _, dependency := range result.Dependencies {
			if !available[strings.ToLower(dependency)] {
				result.MissingDependencies = append(result.MissingDependencies, dependency)
			}
		}
	}
	summary.CompletedAt = time.Now().UTC()
	if failed {
		return summary, fmt.Errorf("one or more imports failed or conflicted; see JSON results")
	}
	return summary, nil
}

func importPackage(ctx context.Context, input, output *os.Root, store storage.Storage, policy *sandbox.Policy, name string) Result {
	result := Result{File: name, Status: "rejected"}
	vsix, err := read(input, name, storage.MaxPackageSize)
	if err != nil {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	result.SHA256 = hash(vsix)
	manifest, err := storage.ReadVSIXManifest(vsix)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	identity := manifest.Metadata.Identity
	version := storage.Version{Version: identity.Version, TargetPlatform: identity.TargetPlatform}
	result.Extension = storage.ExtensionIDWithoutVersion(identity.Publisher, identity.ID) + "@" + version.String()
	for _, property := range manifest.Metadata.Properties.Property {
		if property.ID == storage.DependencyPropertyType && property.Value != "" {
			for _, dependency := range strings.Split(property.Value, ",") {
				if dependency = strings.TrimSpace(dependency); dependency != "" {
					result.Dependencies = append(result.Dependencies, dependency)
				}
			}
		}
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	signature, err := read(input, base+".sigzip", storage.MaxPackageSize)
	if err != nil {
		return readFailure(result, err)
	}
	report, err := read(input, base+".sandbox.json", sandbox.MaxReportSize)
	if err != nil {
		return readFailure(result, err)
	}
	if err := extensionsign.ValidateSignatureArchive(vsix, signature); err != nil {
		result.Reason = err.Error()
		return result
	}
	approval, err := policy.Verify(report, vsix, time.Now().UTC())
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	if err := storage.ValidatePackage(manifest, vsix); err != nil {
		result.Reason = err.Error()
		return result
	}
	target := filepath.Join(identity.Publisher, identity.ID, version.String())
	if _, err := output.Stat(target); err == nil {
		data, err := read(output, filepath.Join(target, ReceiptName), sandbox.MaxReportSize)
		var receipt Receipt
		if err != nil || sandbox.Decode(data, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.SHA256 != result.SHA256 || receipt.SignatureHash != hash(signature) {
			result.Status, result.Reason = "conflict", "version already exists with different bytes or without a trusted import receipt"
			return result
		}
		stored, err := read(output, filepath.Join(target, storage.ExtensionVSIXNameFromManifest(manifest)+".vsix"), storage.MaxPackageSize)
		storedSignature, sigErr := read(output, filepath.Join(target, storage.SignatureArchiveFilename(manifest)), storage.MaxPackageSize)
		if err != nil || sigErr != nil || hash(stored) != result.SHA256 || hash(storedSignature) != receipt.SignatureHash {
			result.Status, result.Reason = "conflict", "published files do not match their import receipt"
			return result
		}
		result.Status = "unchanged"
		return result
	} else if !errors.Is(err, os.ErrNotExist) {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	receipt := Receipt{SchemaVersion: 1, SHA256: result.SHA256, SignatureHash: hash(signature), ImportedAt: time.Now().UTC(), Approval: *approval}
	data, err := json.Marshal(receipt)
	if err != nil {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	_, err = store.AddExtension(ctx, manifest, vsix,
		storage.File{RelativePath: storage.SignatureArchiveFilename(manifest), Content: signature},
		storage.File{RelativePath: ReceiptName, Content: data},
		storage.File{RelativePath: ".sandbox-report.json", Content: report},
	)
	if err != nil {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	result.Status = "imported"
	return result
}

func readFailure(result Result, err error) Result {
	result.Status = "failed"
	if errors.Is(err, os.ErrNotExist) {
		result.Status = "waiting"
	}
	result.Reason = err.Error()
	return result
}

func read(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%s changed while opening", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds size limit", name)
	}
	return data, nil
}

func overlaps(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
