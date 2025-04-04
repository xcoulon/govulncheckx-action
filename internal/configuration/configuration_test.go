package configuration_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xcoulon/govulncheckx-action/internal/configuration"
)

func TestNewConfiguration(t *testing.T) {

	t.Run("empty filename", func(t *testing.T) {
		// when
		c, err := configuration.New("")
		// then
		require.NoError(t, err)
		assert.Empty(t, c.IgnoredVulnerabilities)
	})

	t.Run("empty file", func(t *testing.T) {
		// given
		tempFile, err := os.CreateTemp("", "ignored-vuln-*.yaml")
		require.NoError(t, err)
		// when
		c, err := configuration.New(tempFile.Name())
		// then
		require.NoError(t, err)
		assert.Empty(t, c.IgnoredVulnerabilities)
	})

	t.Run("empty ignored-vulnerabilities", func(t *testing.T) {
		// given
		tempFile, err := os.CreateTemp("", "ignored-vuln-*.yaml")
		fmt.Fprintln(tempFile, "ignored-vulnerabilities:")
		require.NoError(t, err)
		// when
		c, err := configuration.New(tempFile.Name())
		// then
		require.NoError(t, err)
		assert.Empty(t, c.IgnoredVulnerabilities)
	})

	t.Run("some ignored-vulnerabilities", func(t *testing.T) {
		// given
		tempFile, err := os.CreateTemp("", "ignored-vuln-*.yaml")
		fmt.Fprintln(tempFile, "ignored-vulnerabilities:")
		fmt.Fprintln(tempFile, "- GO-2025-0001")
		fmt.Fprintln(tempFile, "- GO-2025-0002")
		require.NoError(t, err)
		// when
		c, err := configuration.New(tempFile.Name())
		// then
		require.NoError(t, err)
		require.Len(t, c.IgnoredVulnerabilities, 2)
		assert.Equal(t, "GO-2025-0001", c.IgnoredVulnerabilities[0])
		assert.Equal(t, "GO-2025-0002", c.IgnoredVulnerabilities[1])
	})

	t.Run("invalid file", func(t *testing.T) {
		// given
		tempFile, err := os.CreateTemp("", "ignored-vuln-*.yaml")
		fmt.Fprintln(tempFile, "ignored-vulnerabilities:")
		fmt.Fprintln(tempFile, "GO-2025-3547")
		require.NoError(t, err)
		// when
		_, err = configuration.New(tempFile.Name())
		// then
		require.Error(t, err)
	})
}
