package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/coder/code-marketplace/filelock"
	"github.com/google/uuid"
)

const IncomingReportName = "import-report.json"

func writeIncomingSummary(root *os.Root, summary *Summary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	name := ".import-report-" + uuid.NewString() + ".part"
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, err = file.Write(append(data, '\n'))
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(name, IncomingReportName)
}

func WriteIncomingFailure(incoming, destination string, started time.Time, cause error) error {
	if incoming == "" || destination == "" || cause == nil {
		return fmt.Errorf("incoming, published storage, and failure are required")
	}
	inputPath, err := filepath.EvalSymlinks(incoming)
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(destination); err == nil {
		outputPath, err = filepath.Abs(resolved)
		if err != nil {
			return err
		}
	}
	inputPath, err = filepath.Abs(inputPath)
	if err != nil {
		return err
	}
	if overlaps(inputPath, outputPath) {
		return fmt.Errorf("incoming and published storage must be separate directories")
	}
	input, err := os.OpenRoot(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	if output, err := os.OpenRoot(outputPath); err == nil {
		defer output.Close()
		inputInfo, err := input.Stat(".")
		if err != nil {
			return err
		}
		outputInfo, err := output.Stat(".")
		if err != nil {
			return err
		}
		if os.SameFile(inputInfo, outputInfo) {
			return fmt.Errorf("incoming and published storage must not be aliases")
		}
		release, err := filelock.Acquire(output, ".ingest.lock")
		if err != nil {
			return err
		}
		defer release()
	}
	return writeIncomingSummary(input, &Summary{StartedAt: started, CompletedAt: time.Now().UTC(), Status: "failed", Error: cause.Error(), Results: []Result{}})
}
