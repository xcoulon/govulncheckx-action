package govulncheck

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/xcoulon/govulncheckx-action/internal/configuration"
	"golang.org/x/vuln/scan"
)

func Scan(ctx context.Context, logger *log.Logger, config configuration.Configuration, path string) ([]*Vulnerability, error) {
	logger.Printf("scan -C %s -format json ./...\n", path)
	// check that the path exists
	fsEntries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, e := range fsEntries {
		logger.Println(e.Name())
	}

	c := scan.Command(ctx, "-C", path, "-format", "json", "./...")
	out := &bytes.Buffer{}
	c.Stdout = out
	c.Stderr = logger.Writer()
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("failed to start golang/govulncheck: %w", err)
	}
	if err := c.Wait(); err != nil {
		return nil, fmt.Errorf("failed while running golang/govulncheck: %w", err)
	}

	// get the vulns
	vulns, err := getVulnerabilities(out.Bytes())
	if err != nil {
		return nil, err
	}

	// remove ignored vulnerabilities
	return pruneIgnoredVulns(logger, vulns, config.IgnoredVulnerabilities), nil
}
