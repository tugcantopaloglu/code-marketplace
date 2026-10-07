package cli_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/code-marketplace/cli"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
)

func TestAddHelp(t *testing.T) {
	t.Parallel()

	cmd := cli.Root()
	cmd.SetArgs([]string{"add", "--help"})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	require.Contains(t, output, "Add an extension", "has help")
}

func TestAdd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// error is the expected error.
		error string
		// extensions are extensions to add.  Use for success cases.
		extensions []testutil.Extension
		// name is the name of the test.
		name string
		// platforms to add for the latest version of each extension.
		platforms []storage.Platform
		// vsixes contains raw bytes of extensions to add.  Use for failure cases.
		vsixes [][]byte
	}{
		{
			name:       "OK",
			extensions: []testutil.Extension{testutil.Extensions[0]},
		},
		{
			name:       "OKPlatforms",
			extensions: []testutil.Extension{testutil.Extensions[0]},
			platforms: []storage.Platform{
				storage.PlatformUnknown,
				storage.PlatformWin32X64,
				storage.PlatformLinuxX64,
				storage.PlatformDarwinX64,
				storage.PlatformWeb,
			},
		},
		{
			name:   "InvalidVSIX",
			error:  "not a valid zip",
			vsixes: [][]byte{{}},
		},
		{
			name: "BulkOK",
			extensions: []testutil.Extension{
				testutil.Extensions[0],
				testutil.Extensions[1],
				testutil.Extensions[2],
				testutil.Extensions[3],
			},
		},
		{
			name:  "BulkInvalid",
			error: "Failed to add 2 extensions: 0.vsix, 1.vsix",
			extensions: []testutil.Extension{
				testutil.Extensions[0],
				testutil.Extensions[1],
				testutil.Extensions[2],
				testutil.Extensions[3],
			},
			vsixes: [][]byte{
				{},
				[]byte("foo"),
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			extdir := t.TempDir()
			count := 0
			create := func(vsix []byte) {
				source := filepath.Join(extdir, fmt.Sprintf("%d.vsix", count))
				err := os.WriteFile(source, vsix, 0o644)
				require.NoError(t, err)
				count++
			}
			for _, vsix := range test.vsixes {
				create(vsix)
			}
			for _, ext := range test.extensions {
				if len(test.platforms) > 0 {
					for _, platform := range test.platforms {
						create(testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion, TargetPlatform: platform}))
					}
				} else {
					create(testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion}))
				}
			}

			// With multiple extensions use bulk add by pointing to the directory
			// otherwise point to the vsix file.  When not using bulk add also test
			// from HTTP.
			sources := []string{extdir}
			if count == 1 {
				sources = []string{filepath.Join(extdir, "0.vsix")}

				handler := func(rw http.ResponseWriter, r *http.Request) {
					var vsix []byte
					if test.vsixes == nil {
						vsix = testutil.CreateVSIXFromExtension(t, test.extensions[0], storage.Version{Version: test.extensions[0].LatestVersion})
					} else {
						vsix = test.vsixes[0]
					}
					_, err := rw.Write(vsix)
					require.NoError(t, err)
				}
				server := httptest.NewServer(http.HandlerFunc(handler))
				defer server.Close()

				sources = append(sources, server.URL)
			}

			for _, source := range sources {
				cmd := cli.Root()
				args := []string{"add", source, "--extensions-dir", extdir}
				cmd.SetArgs(args)
				buf := new(bytes.Buffer)
				cmd.SetOut(buf)

				err := cmd.Execute()
				output := buf.String()

				if test.error != "" {
					require.Error(t, err)
					require.Regexp(t, test.error, err.Error())
				} else {
					require.NoError(t, err)
					require.NotContains(t, output, "Failed to add")
				}

				// Should list all the extensions that worked.
				for _, ext := range test.extensions {
					// Should exist on disk.
					dest := filepath.Join(extdir, ext.Publisher, ext.Name, ext.LatestVersion)
					_, err := os.Stat(dest)
					require.NoError(t, err)
					// Should tell you where it went.
					id := storage.ExtensionIDWithVersion(ext.Publisher, ext.Name, ext.LatestVersion)
					require.Contains(t, output, fmt.Sprintf("Unpacked %s to %s", id, dest))
					// Should mention the dependencies and pack.
					require.Contains(t, output, fmt.Sprintf("%s has %d dep", id, len(ext.Dependencies)))
					if len(ext.Pack) > 0 {
						require.Contains(t, output, fmt.Sprintf("%s is in a pack with %d other", id, len(ext.Pack)))
					} else {
						require.Contains(t, output, fmt.Sprintf("%s is not in a pack", id))
					}
				}
			}
		})
	}
}

func TestAddSignature(t *testing.T) {
	t.Parallel()
	ext := testutil.Extensions[0]
	version := storage.Version{Version: ext.LatestVersion, TargetPlatform: storage.PlatformWin32X64}
	vsix := testutil.CreateVSIXFromExtension(t, ext, version)
	signature := testutil.CreateSignatureArchive(t, vsix)
	input := t.TempDir()
	vsixPath := filepath.Join(input, "extension.vsix")
	signaturePath := filepath.Join(input, "extension.sigzip")
	require.NoError(t, os.WriteFile(vsixPath, vsix, 0o644))
	require.NoError(t, os.WriteFile(signaturePath, signature, 0o644))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/extension.vsix":
			_, _ = w.Write(vsix)
		case "/extension.sigzip":
			_, _ = w.Write(signature)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	for _, tc := range []struct {
		name      string
		source    string
		signature string
		error     string
	}{
		{name: "Local", source: vsixPath, signature: signaturePath},
		{name: "HTTP", source: server.URL + "/extension.vsix", signature: server.URL + "/extension.sigzip"},
		{name: "SignatureNotFound", source: vsixPath, signature: server.URL + "/missing", error: "read signature archive"},
		{name: "BulkSignature", source: input, signature: signaturePath, error: "requires a single VSIX"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			destination := t.TempDir()
			cmd := cli.Root()
			cmd.SetArgs([]string{"add", tc.source, "--signature", tc.signature, "--extensions-dir", destination})
			cmd.SetOut(new(bytes.Buffer))
			err := cmd.Execute()
			if tc.error != "" {
				require.ErrorContains(t, err, tc.error)
				entries, err := os.ReadDir(destination)
				require.NoError(t, err)
				require.Empty(t, entries)
				return
			}
			require.NoError(t, err)
			manifest, err := storage.ReadVSIXManifest(vsix)
			require.NoError(t, err)
			stored, err := os.ReadFile(filepath.Join(destination, ext.Publisher, ext.Name, version.String(), storage.SignatureArchiveFilename(manifest)))
			require.NoError(t, err)
			require.Equal(t, signature, stored)
		})
	}
}

func TestBulkSignaturePairs(t *testing.T) {
	t.Parallel()
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			source := t.TempDir()
			destination := t.TempDir()
			ext := testutil.Extensions[0]
			vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
			require.NoError(t, os.WriteFile(filepath.Join(source, "package.vsix"), vsix, 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(source, "package.vsix.part"), []byte("uploading"), 0o644))
			if signed {
				require.NoError(t, os.WriteFile(filepath.Join(source, "package.sigzip"), testutil.CreateSignatureArchive(t, vsix), 0o644))
			}
			cmd := cli.Root()
			cmd.SetArgs([]string{"add", source, "--require-signature", "--extensions-dir", destination})
			cmd.SetOut(new(bytes.Buffer))
			err := cmd.Execute()
			if signed {
				require.NoError(t, err)
				manifest, err := storage.ReadVSIXManifest(vsix)
				require.NoError(t, err)
				require.FileExists(t, filepath.Join(destination, ext.Publisher, ext.Name, ext.LatestVersion, storage.SignatureArchiveFilename(manifest)))
			} else {
				require.ErrorContains(t, err, "Failed to add 1 extension")
				entries, err := os.ReadDir(destination)
				require.NoError(t, err)
				require.Empty(t, entries)
			}
		})
	}
}
