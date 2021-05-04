package cmd

import (
	"errors"
	"fmt"
	"github.com/ory/kratos/cmd/sql"
	"os"

	"github.com/ory/x/cmdx"

	"github.com/ory/x/viperx"

	"github.com/spf13/cobra"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use: "kratos",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		if !errors.Is(err, cmdx.ErrNoPrintButFail) {
			fmt.Fprintln(RootCmd.ErrOrStderr(), err)
		}
		os.Exit(1)
	}
}

func init() {
	viperx.RegisterConfigFlag(RootCmd, "kratos")

	sql.RegisterCommandRecursive(RootCmd)
}
