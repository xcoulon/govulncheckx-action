package govulncheck_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xcoulon/golvulncheck-action/internal/govulncheck"
)

func TestPruneIgnoreVulns(t *testing.T) {

	t.Run("ignore all vulns", func(t *testing.T) {
		// given
		r := newOpenVexReport()
		ignoredVulns := []string{
			"GO-2025-0001",
			"GO-2025-0002",
			"GO-2025-0003",
		}
		// when
		r.PruneIgnoreVulns(ignoredVulns)
		// then
		assert.Empty(t, r.Statements)
	})

	t.Run("ignore first vuln", func(t *testing.T) {
		// given
		r := newOpenVexReport()
		ignoredVulns := []string{
			"GO-2025-0001",
		}
		// when
		r.PruneIgnoreVulns(ignoredVulns)
		// then
		require.Len(t, r.Statements, 2)
		assert.Equal(t, "GO-2025-0002", r.Statements[0].Vulnerability.Name)
		assert.Equal(t, "GO-2025-0003", r.Statements[1].Vulnerability.Name)
	})

	t.Run("ignore first and last vulns", func(t *testing.T) {
		// given
		r := newOpenVexReport()
		ignoredVulns := []string{
			"GO-2025-0001",
			"GO-2025-0003",
		}
		// when
		r.PruneIgnoreVulns(ignoredVulns)
		// then
		require.Len(t, r.Statements, 1)
		assert.Equal(t, "GO-2025-0002", r.Statements[0].Vulnerability.Name)
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
