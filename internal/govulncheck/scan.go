package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/xcoulon/golvulncheck-action/internal/configuration"
	"golang.org/x/vuln/scan"
)

func Scan(ctx context.Context, config configuration.Configuration, path string, stderr io.Writer) error {
	c := scan.Command(ctx, "-format", "openvex", "-C", path, ".")
	out := &bytes.Buffer{}
	c.Stdout = out
	c.Stderr = stderr
	if err := c.Start(); err != nil {
		return fmt.Errorf("failed to run govulncheck: %w", err)
	}
	if err := c.Wait(); err != nil {
		return fmt.Errorf("failed while running govulncheck: %w", err)
	}
	// check the vulnerabilities in the JSON output and ignore those that are excluded
	d := json.NewDecoder(out)
	r := &OpenVexReport{}
	if err := d.Decode(r); err != nil {
		return fmt.Errorf("failed to decode JSON document: %w", err)
	}
	// remove ignored vulnerabilities
	r.PruneIgnoreVulns(config.IgnoredVulnerabilities)
	if len(r.Statements) > 0 {
		jr, _ := json.MarshalIndent(r, "", "  ")
		fmt.Fprintln(stderr, string(jr))
		return fmt.Errorf("%d vulnerabilities found", len(r.Statements))
	}
	return nil
}
