// Command aegisctl administers an AegisOps deployment from the command line.
//
//	aegisctl user create --email you@example.com --role admin
//	aegisctl user list
//	aegisctl user passwd --email you@example.com
//	aegisctl user disable --email you@example.com
//
// It exists because the API cannot bootstrap itself: every endpoint that could
// create a user requires an authenticated admin, and there is no admin until one
// is created. Seeding one through a migration is the obvious alternative and the
// wrong one — a password in a migration is a password in version control, in
// every clone, and in every CI log.
//
// Passwords are read from a terminal with echo disabled, or from
// AEGISCTL_PASSWORD for automation. They are never accepted as a flag: an
// argument is visible in `ps`, in shell history, and in any process-listing
// metric a monitoring agent collects.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/bishal05das/aegisops-ai/internal/config"
	"github.com/bishal05das/aegisops-ai/internal/database"
	"github.com/bishal05das/aegisops-ai/internal/domain/shared"
	"github.com/bishal05das/aegisops-ai/internal/domain/user"
	"github.com/bishal05das/aegisops-ai/internal/ports"
	"github.com/bishal05das/aegisops-ai/internal/repository/postgres"
	"github.com/bishal05das/aegisops-ai/internal/security/password"
	"github.com/bishal05das/aegisops-ai/internal/security/rbac"
	"github.com/bishal05das/aegisops-ai/internal/version"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return exitUsage
	}

	switch args[0] {
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return exitOK
	case "-version", "--version":
		fmt.Println("aegisctl", version.Get().Short())
		return exitOK
	case "user":
		return runUser(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "aegisctl: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func runUser(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return exitUsage
	}

	sub := args[0]
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	email := fs.String("email", "", "the user's email address")
	name := fs.String("name", "", "the user's display name")
	role := fs.String("role", string(user.RoleViewer), "viewer | operator | admin")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	repo, closeDB, err := openRepo(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}
	defer closeDB()

	switch sub {
	case "create":
		return userCreate(ctx, repo, *email, *name, *role)
	case "list":
		return userList(ctx, repo)
	case "passwd":
		return userPasswd(ctx, repo, *email)
	case "disable":
		return userSetActive(ctx, repo, *email, false)
	case "enable":
		return userSetActive(ctx, repo, *email, true)
	default:
		fmt.Fprintf(os.Stderr, "aegisctl: unknown user subcommand %q\n\n%s", sub, usage)
		return exitUsage
	}
}

func openRepo(ctx context.Context) (ports.UserRepository, func(), error) {
	cfg, err := config.Load(nil)
	if err != nil {
		return nil, nil, err
	}
	db, err := database.Open(ctx, database.FromAppConfig(cfg), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", cfg.Postgres.Safe(), err)
	}
	return postgres.NewUserRepo(db), func() { _ = db.Close() }, nil
}

func userCreate(ctx context.Context, repo ports.UserRepository, email, name, roleName string) int {
	if email == "" {
		fmt.Fprintln(os.Stderr, "aegisctl: --email is required")
		return exitUsage
	}
	role := user.Role(roleName)
	if !role.Valid() {
		fmt.Fprintf(os.Stderr, "aegisctl: --role must be one of: viewer, operator, admin (got %q)\n", roleName)
		return exitUsage
	}

	plaintext, err := readPassword("Password: ", true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}

	clock := shared.SystemClock{}
	u, err := user.New(clock, email, name, role)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitUsage
	}

	hasher := password.NewArgon2Hasher(password.Params{})
	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitUsage
	}
	u.PasswordHash = []byte(hashed)

	if err := repo.Create(ctx, u); err != nil {
		if errors.Is(err, shared.ErrAlreadyExists) {
			fmt.Fprintf(os.Stderr, "aegisctl: a user with email %q already exists\n", u.Email)
			return exitFailed
		}
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}

	fmt.Printf("created %s (%s)\n", u.Email, u.Role)
	fmt.Printf("  id:          %s\n", u.ID)
	fmt.Printf("  permissions: %d\n", len(rbac.Permissions(u.Role)))
	if role == user.RoleAdmin {
		// Worth stating plainly at the moment the account is created.
		fmt.Println("\nThis account can approve high-risk remediations. It cannot approve")
		fmt.Println("actions the policy engine marks forbidden — nothing can.")
	}
	return exitOK
}

func userPasswd(ctx context.Context, repo ports.UserRepository, email string) int {
	if email == "" {
		fmt.Fprintln(os.Stderr, "aegisctl: --email is required")
		return exitUsage
	}

	u, err := repo.GetByEmail(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}

	plaintext, err := readPassword("New password: ", true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}

	hasher := password.NewArgon2Hasher(password.Params{})
	hashed, err := hasher.Hash(plaintext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitUsage
	}
	u.PasswordHash = []byte(hashed)
	u.UpdatedAt = time.Now().UTC()

	if err := repo.Update(ctx, u); err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}

	fmt.Printf("password updated for %s\n", u.Email)
	// Existing sessions are NOT revoked here, and that is a gap worth naming
	// rather than hiding: revoking them needs the session repository, which
	// this command does not open. Until it does, a password change should be
	// followed by a logout-everywhere through the API.
	fmt.Println("note: existing sessions remain valid; use POST /api/v1/auth/logout")
	fmt.Println("      with all_sessions=true to end them.")
	return exitOK
}

func userSetActive(ctx context.Context, repo ports.UserRepository, email string, active bool) int {
	if email == "" {
		fmt.Fprintln(os.Stderr, "aegisctl: --email is required")
		return exitUsage
	}
	u, err := repo.GetByEmail(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}
	u.Active = active
	u.UpdatedAt = time.Now().UTC()
	if err := repo.Update(ctx, u); err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}

	state := "disabled"
	if active {
		state = "enabled"
	}
	fmt.Printf("%s is now %s\n", u.Email, state)
	if !active {
		fmt.Println("note: their access token remains valid until it expires (minutes).")
		fmt.Println("      Refresh is refused immediately, so the session cannot be extended.")
	}
	return exitOK
}

func userList(ctx context.Context, repo ports.UserRepository) int {
	page, err := repo.List(ctx, ports.Page{Limit: 200})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegisctl: %v\n", err)
		return exitFailed
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "EMAIL\tROLE\tACTIVE\tLAST LOGIN\tCREATED")
	for _, u := range page.Items {
		last := "never"
		if u.LastLoginAt != nil {
			last = u.LastLoginAt.Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%t\t%s\t%s\n",
			u.Email, u.Role, u.Active, last, u.CreatedAt.Format("2006-01-02"))
	}
	_ = w.Flush()

	fmt.Printf("\n%d user(s)\n", len(page.Items))
	if len(page.Items) == 0 {
		fmt.Println("\nNo users exist yet. Create the first admin with:")
		fmt.Println("  aegisctl user create --email you@example.com --role admin")
	}
	return exitOK
}

// readPassword reads a password without echoing it.
//
// Never a flag. A password passed as an argument is visible in `ps`, recorded in
// shell history, and collected by any process-listing metric a monitoring agent
// scrapes — the credential leaks to places nobody thinks to check.
//
// AEGISCTL_PASSWORD is honoured for automation, where there is no terminal. That
// is a deliberate weakening: an environment variable is readable from /proc for
// the same user, so it suits CI provisioning a throwaway account and not an
// operator setting their own password.
func readPassword(prompt string, confirm bool) (string, error) {
	if fromEnv := os.Getenv("AEGISCTL_PASSWORD"); fromEnv != "" {
		if err := password.Validate(fromEnv); err != nil {
			return "", err
		}
		return fromEnv, nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New(
			"no terminal available to read a password; set AEGISCTL_PASSWORD for non-interactive use")
	}

	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	plaintext := strings.TrimSpace(string(raw))

	if err := password.Validate(plaintext); err != nil {
		return "", err
	}

	if confirm {
		fmt.Fprint(os.Stderr, "Confirm: ")
		again, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read confirmation: %w", err)
		}
		if plaintext != strings.TrimSpace(string(again)) {
			return "", errors.New("the passwords do not match")
		}
	}
	return plaintext, nil
}

const usage = `aegisctl — administer an AegisOps deployment

Usage:
  aegisctl user create  --email <addr> [--name <name>] [--role viewer|operator|admin]
  aegisctl user list
  aegisctl user passwd  --email <addr>
  aegisctl user disable --email <addr>
  aegisctl user enable  --email <addr>
  aegisctl -version

Passwords are read from the terminal with echo disabled. They are never accepted
as a flag, because an argument is visible in ps and in shell history. For
automation, set AEGISCTL_PASSWORD.

Configuration is read from AEGIS_PG_* in the environment. See .env.example.

Exit codes:
  0  success
  1  operation failed
  2  invalid usage
`
