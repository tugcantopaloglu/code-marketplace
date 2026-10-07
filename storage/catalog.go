package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const catalogFilename = ".catalog.json"

type CatalogDates struct {
	PublishedAt time.Time `json:"publishedAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type catalogStorage interface {
	CatalogDates(context.Context, string, string, Version) (CatalogDates, error)
}

func GetCatalogDates(ctx context.Context, store Storage, publisher, name string, version Version) (CatalogDates, error) {
	if provider, ok := store.(catalogStorage); ok {
		return provider.CatalogDates(ctx, publisher, name, version)
	}
	return CatalogDates{}, nil
}

func (s *Signature) CatalogDates(ctx context.Context, publisher, name string, version Version) (CatalogDates, error) {
	return GetCatalogDates(ctx, s.Storage, publisher, name, version)
}

func (s *Local) CatalogDates(ctx context.Context, publisher, name string, version Version) (CatalogDates, error) {
	if err := ctx.Err(); err != nil {
		return CatalogDates{}, err
	}
	if err := ValidateIdentity(publisher, name, version); err != nil {
		return CatalogDates{}, err
	}
	root, err := os.OpenRoot(s.extdir)
	if err != nil {
		return CatalogDates{}, err
	}
	defer root.Close()
	directory := filepath.Join(publisher, name, version.String())
	file, err := root.Open(filepath.Join(directory, catalogFilename))
	if err == nil {
		data, readErr := readLimited(file, 4096)
		file.Close()
		var dates CatalogDates
		if readErr == nil && json.Unmarshal(data, &dates) == nil && !dates.PublishedAt.IsZero() && !dates.UpdatedAt.IsZero() && !dates.UpdatedAt.Before(dates.PublishedAt) && !dates.UpdatedAt.After(time.Now().UTC()) {
			return dates, nil
		}
	} else if !os.IsNotExist(err) {
		return CatalogDates{}, err
	}
	info, err := root.Stat(filepath.Join(directory, "extension.vsixmanifest"))
	if err != nil {
		return CatalogDates{}, err
	}
	return CatalogDates{PublishedAt: info.ModTime().UTC(), UpdatedAt: info.ModTime().UTC()}, nil
}

func writeCatalog(root *os.Root, dates CatalogDates) error {
	file, err := root.OpenFile(catalogFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(dates); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("write catalog dates: %w", err)
	}
	return nil
}
