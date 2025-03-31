package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/xcoulon/golvulncheck-action/internal/configuration"
	"github.com/xcoulon/golvulncheck-action/internal/govulncheck"
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := NewVulnCheckCmd().Execute()
	if err != nil {
		os.Exit(1)
	}
}

func NewVulnCheckCmd() *cobra.Command {
	var configFile string
	var cmd = &cobra.Command{
		Use:          "vuln-check",
		Short:        "Run govulncheck and exclude vulnerabilities listed in the '--ignored' YAML file",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := configuration.New(configFile)
			if err != nil {
				return err
			}
			return govulncheck.Scan(cmd.Context(), config, args[0], cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&configFile, "config", "", "path to the config file")
	return cmd
}
