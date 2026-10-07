package storage

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

const MaxPackageSize int64 = 512 << 20
const MaxExpandedSize uint64 = 2 << 30
const MaxArchiveEntries = 100000

func ValidateComponent(value string) error {
	if value == "" || len(value) > 128 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return fmt.Errorf("invalid identity component %q: path escapes from parent or invalid name", value)
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("._+-", char) {
			continue
		}
		return fmt.Errorf("invalid identity component %q: path escapes from parent or invalid name", value)
	}
	stem := strings.ToUpper(strings.SplitN(value, ".", 2)[0])
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9') {
		return fmt.Errorf("reserved identity component %q", value)
	}
	return nil
}

func ValidateRelativePath(value string) error {
	if value == "" || strings.ContainsAny(value, "\\:\x00") || strings.HasPrefix(value, "/") || path.Clean(value) != strings.TrimSuffix(value, "/") || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return fmt.Errorf("path escapes from parent: %q", value)
	}
	return nil
}

func ValidateIdentity(publisher, name string, version Version) error {
	for _, value := range []string{publisher, name, version.Version} {
		if err := ValidateComponent(value); err != nil {
			return err
		}
	}
	switch version.TargetPlatform {
	case "", PlatformUniversal, PlatformUnknown, PlatformUndefined, PlatformWin32X64, PlatformWin32Ia32, PlatformWin32Arm64, PlatformLinuxX64, PlatformLinuxArm64, PlatformLinuxArmhf, PlatformAlpineX64, PlatformAlpineArm64, PlatformDarwinX64, PlatformDarwinArm64, PlatformWeb:
		return nil
	default:
		return fmt.Errorf("unsupported target platform %q", version.TargetPlatform)
	}
}

func ValidatePackage(manifest *VSIXManifest, vsix []byte, extra ...File) error {
	if int64(len(vsix)) > MaxPackageSize {
		return fmt.Errorf("VSIX exceeds the %d byte package limit", MaxPackageSize)
	}
	reader, err := zip.NewReader(bytes.NewReader(vsix), int64(len(vsix)))
	if err != nil {
		return err
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	if len(reader.File) > MaxArchiveEntries {
		return fmt.Errorf("VSIX has too many entries")
	}
	var expanded uint64
	seen := make(map[string]bool)
	for _, file := range reader.File {
		if err := ValidateRelativePath(file.Name); err != nil {
			return err
		}
		if file.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("VSIX symlinks are not allowed")
		}
		key := strings.ToLower(strings.TrimSuffix(file.Name, "/"))
		if seen[key] {
			return fmt.Errorf("duplicate VSIX path %q", file.Name)
		}
		seen[key] = true
		if file.UncompressedSize64 > MaxExpandedSize-expanded {
			return fmt.Errorf("VSIX exceeds the expanded size limit")
		}
		expanded += file.UncompressedSize64
	}
	for _, file := range extra {
		if err := ValidateRelativePath(file.RelativePath); err != nil {
			return err
		}
	}
	return nil
}
