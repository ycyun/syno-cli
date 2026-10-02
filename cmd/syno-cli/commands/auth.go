package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

type Login struct {
	SynoClient `group:"Synology Client" namespace:"synology" env-namespace:"SYNOLOGY"`
}

func (cmd *Login) Execute([]string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()
	if err := cmd.Client().Login(ctx); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	fmt.Fprintln(os.Stdout, "logged in successfully")
	return nil
}

type Logout struct {
	SynoClient `group:"Synology Client" namespace:"synology" env-namespace:"SYNOLOGY"`
}

func (cmd *Logout) Execute([]string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()
	if err := cmd.Client().Logout(ctx); err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	fmt.Fprintln(os.Stdout, "logged out successfully")
	return nil
}
