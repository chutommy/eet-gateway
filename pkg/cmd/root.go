package cmd

// Execute executes the root command.
func Execute() {
	initCommands()
	eetgCmd.AddCommand(versionCmd, initCmd, serveCmd)
	_ = eetgCmd.Execute()
}

func initCommands() {
	initEETGCmd()
	initInitCmd()
	initServeCmd()
}
