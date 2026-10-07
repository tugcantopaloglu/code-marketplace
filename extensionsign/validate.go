package extensionsign

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"

	"golang.org/x/xerrors"
)

const maxSignatureFileSize = 16 << 20

func ValidateSignatureArchive(vsix, archive []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return xerrors.Errorf("not a valid signature ZIP: %w", err)
	}
	if len(reader.File) != 2 {
		return xerrors.Errorf("signature archive must contain exactly .signature.manifest and .signature.p7s")
	}
	files := make(map[string][]byte, 2)
	for _, file := range reader.File {
		if file.Name != ".signature.manifest" && file.Name != ".signature.p7s" {
			return xerrors.Errorf("unexpected signature entry %q", file.Name)
		}
		if _, ok := files[file.Name]; ok {
			return xerrors.Errorf("duplicate signature entry %q", file.Name)
		}
		if file.UncompressedSize64 == 0 || file.UncompressedSize64 > maxSignatureFileSize {
			return xerrors.Errorf("signature entry %q must contain between 1 and %d bytes", file.Name, maxSignatureFileSize)
		}
		entry, err := file.Open()
		if err != nil {
			return xerrors.Errorf("open signature entry %q: %w", file.Name, err)
		}
		content, err := io.ReadAll(io.LimitReader(entry, maxSignatureFileSize+1))
		entry.Close()
		if err != nil {
			return xerrors.Errorf("read signature entry %q: %w", file.Name, err)
		}
		if len(content) == 0 || len(content) > maxSignatureFileSize {
			return xerrors.Errorf("invalid signature entry size for %q", file.Name)
		}
		files[file.Name] = content
	}
	var manifest SignatureManifest
	if err := json.Unmarshal(files[".signature.manifest"], &manifest); err != nil {
		return xerrors.Errorf("decode signature manifest: %w", err)
	}
	actual, err := FileManifest(bytes.NewReader(vsix))
	if err != nil {
		return xerrors.Errorf("hash VSIX: %w", err)
	}
	if err := actual.Equal(manifest.Package); err != nil {
		return xerrors.Errorf("signature archive does not match VSIX: %w", err)
	}
	return nil
}
