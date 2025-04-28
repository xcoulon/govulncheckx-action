package govulncheck_test

import (
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xcoulon/govulncheckx-action/internal/configuration"
	"github.com/xcoulon/govulncheckx-action/internal/govulncheck"
)

func TestPruneIgnoreVulns(t *testing.T) {
	logger := log.Default()

	t.Run("ignore all vulns", func(t *testing.T) {
		// given
		r := newOpenVexReport()
		ignoredVulns := []configuration.Vulnerability{
			{
				ID:      "GO-2025-0001",
				Expires: time.Date(2200, 5, 10, 0, 0, 0, 0, time.UTC),
				Info:    "https://pkg.go.dev/vuln/GO-2025-0001",
			},
			{
				ID:      "GO-2025-0002",
				Expires: time.Date(2200, 5, 10, 0, 0, 0, 0, time.UTC),
				Info:    "https://pkg.go.dev/vuln/GO-2025-0002",
			},
			{
				ID:      "GO-2025-0003",
				Expires: time.Date(2200, 5, 10, 0, 0, 0, 0, time.UTC),
				Info:    "https://pkg.go.dev/vuln/GO-2025-0003",
			},
		}
		// when
		r.PruneIgnoreVulns(logger, ignoredVulns)
		// then
		assert.Empty(t, r.Statements)
	})

	t.Run("ignore first vuln", func(t *testing.T) {
		// given
		r := newOpenVexReport()
		ignoredVulns := []configuration.Vulnerability{
			{
				ID:      "GO-2025-0001",
				Expires: time.Date(2200, 5, 10, 0, 0, 0, 0, time.UTC),
				Info:    "https://pkg.go.dev/vuln/GO-2025-0001",
			},
		}
		// when
		r.PruneIgnoreVulns(logger, ignoredVulns)
		// then
		require.Len(t, r.Statements, 2)
		assert.Equal(t, "GO-2025-0002", r.Statements[0].Vulnerability.Name)
		assert.Equal(t, "GO-2025-0003", r.Statements[1].Vulnerability.Name)
	})

	t.Run("ignore first and third vulns", func(t *testing.T) {
		// given
		r := newOpenVexReport()
		ignoredVulns := []configuration.Vulnerability{
			{
				ID:      "GO-2025-0001",
				Expires: time.Date(2200, 5, 10, 0, 0, 0, 0, time.UTC),
				Info:    "https://pkg.go.dev/vuln/GO-2025-0001",
			},

			{
				ID:      "GO-2025-0003",
				Expires: time.Date(2200, 5, 10, 0, 0, 0, 0, time.UTC),
				Info:    "https://pkg.go.dev/vuln/GO-2025-0003",
			},
		}
		// when
		r.PruneIgnoreVulns(logger, ignoredVulns)
		// then
		require.Len(t, r.Statements, 1)
		assert.Equal(t, "GO-2025-0002", r.Statements[0].Vulnerability.Name)
	})

	t.Run("need to revaluate vulnerability", func(t *testing.T) {
		// given
		r := newOpenVexReport()
		ignoredVulns := []configuration.Vulnerability{
			{
				ID:      "GO-2025-0001",
				Expires: time.Date(2020, 5, 10, 0, 0, 0, 0, time.UTC),
				Info:    "https://pkg.go.dev/vuln/GO-2025-0001",
			},
		}
		// when
		r.PruneIgnoreVulns(logger, ignoredVulns)
		// then
		require.Len(t, r.Statements, 3)
		assert.Equal(t, "GO-2025-0001", r.Statements[0].Vulnerability.Name)
		assert.Equal(t, "GO-2025-0002", r.Statements[1].Vulnerability.Name)
		assert.Equal(t, "GO-2025-0003", r.Statements[2].Vulnerability.Name)
	})

}

func newOpenVexReport() *govulncheck.OpenVexReport {
	r := &govulncheck.OpenVexReport{}
	r.Statements = []govulncheck.Statement{
		{
			Vulnerability: govulncheck.Vulnerability{
				Name: "GO-2025-0001",
			},
			Status: govulncheck.Affected,
		},
		{
			Vulnerability: govulncheck.Vulnerability{
				Name: "GO-2025-0002",
			},
			Status: govulncheck.Affected,
		},
		{
			Vulnerability: govulncheck.Vulnerability{
				Name: "GO-2025-0003",
			},
			Status: govulncheck.Affected,
		},
		{
			Vulnerability: govulncheck.Vulnerability{
				Name: "GO-2025-0004",
			},
			Status: govulncheck.NotAffected,
		},
	}
	return r
}
