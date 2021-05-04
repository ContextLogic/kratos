package sql

import (
	"context"
	"fmt"
	"github.com/gobuffalo/pop/v5"
	"github.com/ory/kratos/courier"
	"github.com/ory/kratos/driver/configuration"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/viperx"
	"github.com/spf13/cobra"
)

var logger *logrusx.Logger

var runSQLCmd = &cobra.Command{
	Use:   "run-sql",
	Short: "Run SQL query",
	Run: func(cmd *cobra.Command, args []string) {
		logger = viperx.InitializeConfig("kratos", "", logger)

		l := logrusx.New("ORY Kratos", "v0")
		c := configuration.NewViperProvider(l, false)
		pool, idlePool, connMaxLifetime, cleanedDSN := sqlcon.ParseConnectionOptions(l, c.DSN())
		connection, err := pop.NewConnection(&pop.ConnectionDetails{
			URL:             sqlcon.FinalizeDSN(l, cleanedDSN),
			IdlePool:        idlePool,
			ConnMaxLifetime: connMaxLifetime,
			Pool:            pool,
		})

		if err != nil {
			l.WithError(err).Warnf("Unable to connect to database, retrying.")
			panic(err)
		}

		connection.Open()
		connection = connection.WithContext(context.Background())

		// retrieve all queued messages
		var messages []courier.Message
		q := "SELECT * FROM courier_messages WHERE status = ?"
		err = connection.RawQuery(q, courier.MessageStatusQueued).All(&messages)

		if err != nil {
			fmt.Println(sqlcon.HandleError(err).Error())
			return
		}

		var isDryRun = (len(args) == 0) || (len(args) > 0 && args[0] != "run")

		if isDryRun {
			fmt.Println("DRY-RUN mode")
		}

		fmt.Printf("Fetched queued messages: %d", len(messages))
		fmt.Println()

		for index, msg := range messages {
			fmt.Printf("%d / %s / '%s' - ", index, msg.ID, msg.Recipient)

			if isEmailValid(msg.Recipient) {
				fmt.Println("valid")
			} else {
				fmt.Print("invalid, marking as processed...")

				if isDryRun {
					fmt.Println("skipping in dry-run mode")
					continue
				}

				q := "UPDATE courier_messages SET status = ? WHERE id = ?"
				affectedCount, err := connection.RawQuery(q, courier.MessageStatusSent, msg.ID).ExecWithCount()
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
	err := ValidateFormat(e)
	if err != nil {
		return false
	}

	err = ValidateHost(e)
	if err != nil {
		return false
	}

	return true
}

func RegisterCommandRecursive(parent *cobra.Command) {
	parent.AddCommand(runSQLCmd)
}

