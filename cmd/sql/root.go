package sql

import (
	"context"
	"fmt"
	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/internal/clihelpers"
	"github.com/ory/kratos/x"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/viperx"
	"github.com/spf13/cobra"
	"regexp"
)

var logger *logrusx.Logger
var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

var runSQLCmd = &cobra.Command{
	Use:   "run-sql",
	Short: "Run SQL query",
	Run: func(cmd *cobra.Command, args []string) {
		logger = viperx.InitializeConfig("kratos", "", logger)
		x.WatchAndValidateViper(logger)
		d := driver.MustNewDefaultDriver(logger, clihelpers.BuildVersion, clihelpers.BuildTime, clihelpers.BuildGitHash, false)

		// retrieve all queued messages
		var messages []courier.Message
		q := "SELECT * FROM courier_messages WHERE status = ?"
		err := d.Registry().Persister().GetConnection(context.Background()).RawQuery(q, courier.MessageStatusQueued).All(&messages)

		if err != nil {
			fmt.Println(sqlcon.HandleError(err).Error())
			return
		}

		fmt.Printf("Fetched queued messages: %d", len(messages))
		fmt.Println()

		for index, msg := range messages {
			fmt.Printf("%d / %s / '%s' - ", index, msg.ID, msg.Recipient)

			if isEmailValid(msg.Recipient) {
				fmt.Println("valid")
			} else {
				fmt.Print("invalid, marking as processed...")
				q := "UPDATE courier_messages SET status = ? WHERE id = ?"
				affectedCount, err := d.Registry().Persister().GetConnection(context.Background()).RawQuery(q, courier.MessageStatusSent, msg.ID).ExecWithCount()
				if err != nil {
					fmt.Println(sqlcon.HandleError(err).Error())
					return
				}
				if affectedCount != 1 {
					fmt.Println("Number of affected rows is not equal to 1")
					return
				}
				fmt.Println("done!")
			}

		}
	},
}

func isEmailValid(e string) bool {
	if len(e) < 3 && len(e) > 254 {
		return false
	}
	if !emailRegex.MatchString(e) {
		return false
	}

	return true
}

func RegisterCommandRecursive(parent *cobra.Command) {
	parent.AddCommand(runSQLCmd)
}
