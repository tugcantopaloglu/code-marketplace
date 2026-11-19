package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/extensionsign"
	"github.com/coder/code-marketplace/filelock"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/google/uuid"
)

const ReceiptName = ".import-receipt.json"
const internalReportName = ".internal-report.json"

type Receipt struct {
	SchemaVersion int                         `json:"schemaVersion"`
	SHA256        string                      `json:"sha256"`
	SignatureHash string                      `json:"signatureSha256,omitempty"`
	ImportedAt    time.Time                   `json:"importedAt"`
	SandboxMode   string                      `json:"sandboxMode,omitempty"`
	Approval      *sandbox.Approval           `json:"sandbox,omitempty"`
	Publisher     *publisher.Approval         `json:"publisher,omitempty"`
	Internal      *publisher.InternalApproval `json:"internal,omitempty"`
}

type Result struct {
	File                string                      `json:"file"`
	Extension           string                      `json:"extension,omitempty"`
	SHA256              string                      `json:"sha256,omitempty"`
	Status              string                      `json:"status"`
	SandboxMode         string                      `json:"sandboxMode"`
	Reason              string                      `json:"reason,omitempty"`
	Dependencies        []string                    `json:"dependencies,omitempty"`
	MissingDependencies []string                    `json:"missingDependencies,omitempty"`
	Publisher           *publisher.Approval         `json:"publisher,omitempty"`
	Internal            *publisher.InternalApproval `json:"internal,omitempty"`
	ArchiveStatus       string                      `json:"archiveStatus,omitempty"`
	ArchivedTo          string                      `json:"archivedTo,omitempty"`
	ArchiveError        string                      `json:"archiveError,omitempty"`
	RecoveryDir         string                      `json:"recoveryDir,omitempty"`
	sourceHashes        map[string]string
}

type Summary struct {
	StartedAt    time.Time `json:"startedAt"`
	CompletedAt  time.Time `json:"completedAt,omitzero"`
	Status       string    `json:"status"`
	Error        string    `json:"error,omitempty"`
	Results      []Result  `json:"results"`
	RecoveryDirs []string  `json:"recoveryDirs,omitempty"`
}

type Options struct {
	Incoming            string
	Storage             string
	Policy              *sandbox.Policy
	SandboxMode         string
	PublisherPolicy     *publisher.Policy
	InternalPolicy      *publisher.InternalPolicy
	InternalAutoSign    *InternalAutoSign
	Logger              slog.Logger
	Processed           string
	WriteIncomingReport bool
}

func Run(ctx context.Context, options Options) (summary *Summary, runErr error) {
	started := time.Now().UTC()
	defer func() {
		if summary == nil && runErr != nil && options.WriteIncomingReport {
			if err := WriteIncomingFailure(options.Incoming, options.Storage, started, runErr); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("write incoming failure report: %w", err))
			}
		}
	}()
	if options.SandboxMode == "" {
		options.SandboxMode = "required"
	}
	if options.SandboxMode != "required" && options.SandboxMode != "disabled" {
		return nil, fmt.Errorf("sandbox mode must be required or disabled")
	}
	skipInternalSandbox := options.InternalAutoSign != nil && options.InternalAutoSign.SkipSandbox
	sandboxRequired := options.SandboxMode == "required" || options.InternalPolicy != nil && !skipInternalSandbox
	if sandboxRequired && options.Policy == nil || options.Policy != nil && (len(options.Policy.Keys) == 0 || options.Policy.MaxAge <= 0) {
		return nil, fmt.Errorf("trusted sandbox approval is mandatory for scheduled imports")
	}
	if options.SandboxMode == "disabled" && options.InternalPolicy == nil && options.Policy != nil {
		return nil, fmt.Errorf("sandbox policy must be omitted in disabled mode")
	}
	if options.PublisherPolicy == nil {
		return nil, fmt.Errorf("publisher policy is mandatory; explicitly select any to disable publisher restrictions")
	}
	if err := options.PublisherPolicy.Validate(); err != nil {
		return nil, err
	}
	if options.InternalAutoSign != nil {
		if err := options.InternalAutoSign.validate(options.InternalPolicy); err != nil {
			return nil, err
		}
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
	summary = &Summary{StartedAt: started, Status: "running", Results: []Result{}}
	defer func() {
		summary.CompletedAt = time.Now().UTC()
		summary.Status = "completed"
		if runErr != nil {
			summary.Status, summary.Error = "failed", runErr.Error()
		}
		data, err := json.Marshal(summary)
		if err == nil {
			err = storage.WritePrivateFile(output, ".last-import.json", data)
		}
		if err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("persist import results: %w", err))
			summary.Status, summary.Error = "failed", runErr.Error()
		}
		if options.WriteIncomingReport {
			if err := writeIncomingSummary(input, summary); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("write incoming report: %w", err))
				summary.Status, summary.Error = "failed", runErr.Error()
			}
		}
	}()
	if options.WriteIncomingReport {
		if err := writeIncomingSummary(input, summary); err != nil {
			return summary, err
		}
	}
	var processed *os.Root
	if options.Processed != "" {
		processed, err = openProcessed(options.Processed, incoming, destination, input, output)
		if err != nil {
			return summary, err
		}
		defer processed.Close()
	}
	store, err := storage.NewStorage(ctx, &storage.Options{ExtDir: destination, Logger: options.Logger, Immutable: true})
	if err != nil {
		return summary, err
	}
	entries, err := os.ReadDir(incoming)
	if err != nil {
		return summary, err
	}
	var failed bool
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".vsix") {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), ".archive-") {
				if _, err := uuid.Parse(strings.TrimPrefix(entry.Name(), ".archive-")); err == nil {
					summary.RecoveryDirs = append(summary.RecoveryDirs, entry.Name())
					failed = true
				}
			}
			continue
		}
		result := importPackage(ctx, input, output, store, options, entry.Name())
		if processed != nil && (result.Status == "imported" || result.Status == "unchanged") {
			result.ArchivedTo, result.RecoveryDir, err = archivePackage(ctx, input, processed, result)
			result.ArchiveStatus = "archived"
			if err != nil {
				result.ArchiveStatus, result.ArchiveError = "failed", err.Error()
				failed = true
			}
		}
		summary.Results = append(summary.Results, result)
		failed = failed || result.Status == "failed" || result.Status == "conflict"
		if options.WriteIncomingReport {
			if err := writeIncomingSummary(input, summary); err != nil {
				return summary, err
			}
		}
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
	if failed {
		return summary, fmt.Errorf("one or more imports or archive operations failed, conflicted, or require recovery; see JSON results")
	}
	return summary, nil
}

func importPackage(ctx context.Context, input, output *os.Root, store storage.Storage, options Options, name string) Result {
	result := Result{File: name, Status: "rejected", SandboxMode: options.SandboxMode}
	vsix, source, err := readWithInfo(input, name, storage.MaxPackageSize)
	if err != nil {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	result.SHA256 = hash(vsix)
	result.sourceHashes = map[string]string{name: result.SHA256}
	manifest, err := storage.ReadVSIXManifest(vsix)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	identity := manifest.Metadata.Identity
	version := storage.Version{Version: identity.Version, TargetPlatform: identity.TargetPlatform}
	result.Extension = storage.ExtensionIDWithoutVersion(identity.Publisher, identity.ID) + "@" + version.String()
	revoked, err := storage.IsRevoked(output, identity.Publisher, identity.ID, version)
	if err != nil {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	if revoked {
		result.Reason = "this version was revoked by an administrator"
		return result
	}
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
	internal := options.InternalPolicy.Handles(manifest)
	prefixed := options.InternalAutoSign != nil && strings.HasPrefix(base, "internal-")
	if prefixed && !internal {
		result.Reason = "extension is outside the internal policy for automatic signing"
		return result
	}
	var signature, internalReport []byte
	var signatureHash string
	autoSign := false
	internalName := base + publisher.InternalReportSuffix
	if internal {
		result.SandboxMode = "required"
		skipSandbox := prefixed && options.InternalAutoSign.SkipSandbox
		internalReport, err = read(input, internalName, sandbox.MaxReportSize)
		if skipSandbox || prefixed && errors.Is(err, os.ErrNotExist) {
			if err := options.InternalAutoSign.authorize(source, options.InternalPolicy, manifest); err != nil {
				result.Reason = err.Error()
				return result
			}
		}
		if skipSandbox {
			result.SandboxMode = "disabled"
		}
		switch {
		case err == nil:
			result.Internal, err = options.InternalPolicy.Verify(internalReport, vsix, manifest, time.Now().UTC())
			if err != nil {
				result.Reason = err.Error()
				return result
			}
			result.sourceHashes[internalName] = result.Internal.ReportSHA256
		case prefixed && errors.Is(err, os.ErrNotExist):
			autoSign = true
		default:
			return readFailure(result, err)
		}
	} else {
		signature, err = read(input, base+".sigzip", storage.MaxPackageSize)
		if err != nil {
			return readFailure(result, err)
		}
		signatureHash = hash(signature)
		result.sourceHashes[base+".sigzip"] = signatureHash
		if err := extensionsign.ValidateSignatureArchive(vsix, signature); err != nil {
			result.Reason = err.Error()
			return result
		}
	}
	var report []byte
	var approval *sandbox.Approval
	if result.SandboxMode == "required" {
		if options.Policy == nil {
			result.Status, result.Reason = "waiting", "this package requires configured sandbox trust and a signed scan report"
			return result
		}
		report, err = read(input, base+".sandbox.json", sandbox.MaxReportSize)
		if err != nil {
			return readFailure(result, err)
		}
		result.sourceHashes[base+".sandbox.json"] = hash(report)
		approval, err = options.Policy.Verify(report, vsix, time.Now().UTC())
		if err != nil {
			result.Reason = err.Error()
			return result
		}
	}
	if err := storage.ValidatePackage(manifest, vsix); err != nil {
		result.Reason = err.Error()
		return result
	}
	if autoSign {
		internalReport, result.Internal, err = options.InternalAutoSign.sign(input, internalName, vsix, manifest, options.InternalPolicy)
		if err != nil {
			result.Status, result.Reason = "failed", err.Error()
			return result
		}
		result.sourceHashes[internalName] = result.Internal.ReportSHA256
	}
	var publisherReport []byte
	publisherRequired := result.Internal == nil && options.PublisherPolicy.Mode != "any"
	if publisherRequired {
		publisherReport, err = read(input, base+".publisher.json", sandbox.MaxReportSize)
		if err != nil {
			return readFailure(result, err)
		}
		result.sourceHashes[base+".publisher.json"] = hash(publisherReport)
		result.Publisher, err = options.PublisherPolicy.Verify(publisherReport, vsix, signature, manifest, time.Now().UTC())
		if err != nil {
			result.Reason = err.Error()
			return result
		}
	}
	var privateManifest []byte
	if result.Internal != nil {
		privateManifest, err = internalMarketplaceManifest(manifest)
		if err != nil {
			result.Status, result.Reason = "failed", err.Error()
			return result
		}
	}
	target := filepath.Join(identity.Publisher, identity.ID, version.String())
	if _, err := output.Stat(target); err == nil {
		data, err := read(output, filepath.Join(target, ReceiptName), sandbox.MaxReportSize)
		var receipt Receipt
		if err != nil || sandbox.Decode(data, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.SHA256 != result.SHA256 || receipt.SignatureHash != signatureHash || (receipt.Internal == nil) != (result.Internal == nil) {
			result.Status, result.Reason = "conflict", "version already exists with different bytes or without a trusted import receipt"
			return result
		}
		if publisherRequired && receipt.Publisher == nil {
			result.Status, result.Reason = "conflict", "existing version has no publisher provenance receipt; explicit migration is required"
			return result
		}
		stored, err := read(output, filepath.Join(target, storage.ExtensionVSIXNameFromManifest(manifest)+".vsix"), storage.MaxPackageSize)
		if err != nil || hash(stored) != result.SHA256 {
			result.Status, result.Reason = "conflict", "published files do not match their import receipt"
			return result
		}
		if receipt.Internal != nil {
			storedReport, reportErr := read(output, filepath.Join(target, internalReportName), sandbox.MaxReportSize)
			storedManifest, manifestErr := read(output, filepath.Join(target, "extension.vsixmanifest"), 2<<20)
			if reportErr != nil || manifestErr != nil || hash(storedReport) != receipt.Internal.ReportSHA256 || !slices.Equal(storedManifest, privateManifest) || (receipt.SandboxMode != "disabled" && receipt.Approval == nil) {
				result.Status, result.Reason = "conflict", "published internal package is missing approved release metadata"
				return result
			}
		} else {
			storedSignature, sigErr := read(output, filepath.Join(target, storage.SignatureArchiveFilename(manifest)), storage.MaxPackageSize)
			if sigErr != nil || hash(storedSignature) != receipt.SignatureHash {
				result.Status, result.Reason = "conflict", "published files do not match their import receipt"
				return result
			}
		}
		if result.SandboxMode == "required" && (receipt.SandboxMode == "disabled" || receipt.Approval == nil) {
			receipt.SandboxMode, receipt.Approval = "required", approval
			data, err := json.Marshal(receipt)
			var versionRoot *os.Root
			if err == nil {
				versionRoot, err = output.OpenRoot(target)
			}
			if err == nil {
				err = storage.WritePrivateFile(versionRoot, ".sandbox-report.json", report)
				if err == nil {
					err = storage.WritePrivateFile(versionRoot, ReceiptName, data)
				}
				versionRoot.Close()
			}
			if err != nil {
				result.Status, result.Reason = "failed", err.Error()
				return result
			}
			result.Reason = "existing package now has authenticated sandbox approval"
		}
		result.Status = "unchanged"
		return result
	} else if !errors.Is(err, os.ErrNotExist) {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	receipt := Receipt{SchemaVersion: 1, SHA256: result.SHA256, SignatureHash: signatureHash, ImportedAt: time.Now().UTC(), SandboxMode: result.SandboxMode, Approval: approval, Publisher: result.Publisher, Internal: result.Internal}
	data, err := json.Marshal(receipt)
	if err != nil {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	files := []storage.File{{RelativePath: ReceiptName, Content: data}}
	if result.Internal != nil {
		files = append(files, storage.File{RelativePath: internalReportName, Content: internalReport}, storage.File{RelativePath: "extension.vsixmanifest", Content: privateManifest})
	} else {
		files = append(files, storage.File{RelativePath: storage.SignatureArchiveFilename(manifest), Content: signature})
	}
	if approval != nil {
		files = append(files, storage.File{RelativePath: ".sandbox-report.json", Content: report})
	}
	if result.Publisher != nil {
		files = append(files, storage.File{RelativePath: ".publisher-report.json", Content: publisherReport})
	}
	_, err = store.AddExtension(ctx, manifest, vsix, files...)
	if err != nil {
		result.Status, result.Reason = "failed", err.Error()
		return result
	}
	result.Status = "imported"
	return result
}

func internalMarketplaceManifest(manifest *storage.VSIXManifest) ([]byte, error) {
	properties := &manifest.Metadata.Properties.Property
	*properties = slices.DeleteFunc(*properties, func(property storage.VSIXProperty) bool {
		return strings.EqualFold(string(property.ID), string(storage.PrivateMarketplaceProperty))
	})
	*properties = append(*properties, storage.VSIXProperty{ID: storage.PrivateMarketplaceProperty, Value: "true"})
	manifest.Assets.Asset = slices.DeleteFunc(manifest.Assets.Asset, func(asset storage.VSIXAsset) bool {
		return strings.EqualFold(string(asset.Type), string(storage.VSIXSignatureType)) ||
			strings.EqualFold(string(asset.Type), string(storage.VSIXAssetType))
	})
	return xml.Marshal(manifest)
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
	data, _, err := readWithInfo(root, name, limit)
	return data, err
}

func readWithInfo(root *os.Root, name string, limit int64) ([]byte, os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s must be a regular file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, nil, fmt.Errorf("%s changed while opening", name)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("%s exceeds size limit", name)
	}
	return data, opened, nil
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
