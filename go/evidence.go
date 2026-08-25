package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
)

// HashFile calculates SHA-256, MD5, and byte size of a file.
func HashFile(filePath string) (string, string, int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", "", 0, err
	}
	defer f.Close()

	hSha := sha256.New()
	hMd5 := md5.New()
	w := io.MultiWriter(hSha, hMd5)

	n, err := io.Copy(w, f)
	if err != nil {
		return "", "", 0, err
	}

	return hex.EncodeToString(hSha.Sum(nil)), hex.EncodeToString(hMd5.Sum(nil)), n, nil
}

// IndexEvidenceDirectory recursively scans a directory, computing cryptographic digests.
func IndexEvidenceDirectory(dirPath string, followSymlinks bool) ([]Evidence, error) {
	absDir, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("invalid directory path: %w", err)
	}

	var results []Evidence
	count := 0

	err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}

		isSymlink := (info.Mode() & os.ModeSymlink) != 0
		if isSymlink && !followSymlinks {
			return nil
		}

		var s256, m5 string
		var size int64 = info.Size()

		if !isSymlink {
			s256, m5, size, _ = HashFile(path)
		} else {
			s256 = "-"
			m5 = "-"
		}

		ext := filepath.Ext(path)
		mimeType := mime.TypeByExtension(ext)
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		rel, _ := filepath.Rel(absDir, path)
		count++
		results = append(results, Evidence{
			ID:           fmt.Sprintf("EVID-%03d", count),
			RelativePath: rel,
			Filename:     info.Name(),
			SizeBytes:    size,
			MIMEType:     mimeType,
			SHA256:       s256,
			MD5:          m5,
			MTime:        info.ModTime().UTC(),
			IsSymlink:    isSymlink,
		})
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk error: %w", err)
	}

	return results, nil
}

// HashStdin computes cryptographic checksums for standard input.
func HashStdin() (string, string, int64, error) {
	hSha := sha256.New()
	hMd5 := md5.New()
	w := io.MultiWriter(hSha, hMd5)
	n, err := io.Copy(w, os.Stdin)
	if err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(hSha.Sum(nil)), hex.EncodeToString(hMd5.Sum(nil)), n, nil
}
