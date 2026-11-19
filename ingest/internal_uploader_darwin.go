package ingest

import (
	"fmt"
	"os"
)

func verifyInternalUploader(os.FileInfo, uint32) error {
	return fmt.Errorf("automatic internal signing requires Linux file ownership")
}
