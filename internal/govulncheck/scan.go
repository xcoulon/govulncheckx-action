package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/xcoulon/govulncheckx-action/internal/configuration"
	"golang.org/x/vuln/scan"
)

func Scan(ctx context.Context, logger *log.Logger, config configuration.Configuration, path string) (*OpenVexReport, error) {
	logger.Printf("scan -C %s -format openvex ./...\n", path)
	// check that the path exists
	fsEntries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, e := range fsEntries {
		logger.Println(e.Name())
	}

	c := scan.Command(ctx, "-C", path, "-format", "openvex", "./...")
	out := &bytes.Buffer{}
	c.Stdout = out
	c.Stderr = logger.Writer()
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("failed to start golang/govulncheck: %w", err)
	}
	if err := c.Wait(); err != nil {
		return nil, fmt.Errorf("failed while running golang/govulncheck: %w", err)
	}
	// check the vulnerabilities in the JSON output and ignore those that are excluded
	d := json.NewDecoder(out)
	r := &OpenVexReport{}
	if err := d.Decode(r); err != nil {
		return nil, fmt.Errorf("failed to decode the vulnerability report: %w", err)
	}
	// remove ignored vulnerabilities
	r.PruneIgnoreVulns(config.IgnoredVulnerabilities)
	return r, nil
}
