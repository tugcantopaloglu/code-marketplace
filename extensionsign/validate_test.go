package extensionsign_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/code-marketplace/extensionsign"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
)

func TestValidateSignatureArchive(t *testing.T) {
	t.Parallel()
	ext := testutil.Extensions[0]
	vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
	manifest, err := extensionsign.GenerateSignatureManifest(vsix)
	require.NoError(t, err)
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	type entry struct {
		name string
		data []byte
	}
	archive := func(entries ...entry) []byte {
		var buf bytes.Buffer
		writer := zip.NewWriter(&buf)
		for _, item := range entries {
			file, err := writer.Create(item.name)
			require.NoError(t, err)
			_, err = file.Write(item.data)
			require.NoError(t, err)
		}
		require.NoError(t, writer.Close())
		return buf.Bytes()
	}
	manifestEntry := entry{".signature.manifest", manifestBytes}
	signatureEntry := entry{".signature.p7s", []byte("test signature payload")}
	cases := []struct {
		name    string
		vsix    []byte
		archive []byte
		error   string
	}{
		{name: "MatchingPackage", vsix: vsix, archive: testutil.CreateSignatureArchive(t, vsix)},
		{name: "DifferentPackage", vsix: append(append([]byte(nil), vsix...), 1), archive: testutil.CreateSignatureArchive(t, vsix), error: "does not match VSIX"},
		{name: "NotZIP", vsix: vsix, archive: []byte("invalid"), error: "not a valid signature ZIP"},
		{name: "MissingSignature", vsix: vsix, archive: archive(manifestEntry), error: "must contain exactly"},
		{name: "ExtraEntry", vsix: vsix, archive: archive(manifestEntry, signatureEntry, entry{"extra", []byte("x")}), error: "must contain exactly"},
		{name: "DuplicateEntry", vsix: vsix, archive: archive(manifestEntry, manifestEntry), error: "duplicate signature entry"},
		{name: "EmptySignature", vsix: vsix, archive: archive(manifestEntry, entry{".signature.p7s", nil}), error: "must contain between"},
		{name: "InvalidManifest", vsix: vsix, archive: archive(entry{".signature.manifest", []byte("invalid")}, signatureEntry), error: "decode signature manifest"},
		{name: "UnexpectedPath", vsix: vsix, archive: archive(entry{"../.signature.manifest", manifestBytes}, signatureEntry), error: "unexpected signature entry"},
		{name: "OversizedEntry", vsix: vsix, archive: archive(manifestEntry, entry{".signature.p7s", bytes.Repeat([]byte("x"), (16<<20)+1)}), error: "must contain between"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := extensionsign.ValidateSignatureArchive(tc.vsix, tc.archive)
			if tc.error == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.error)
			}
		})
	}
}
