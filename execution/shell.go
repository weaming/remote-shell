package execution

import (
	"fmt"
	"os/exec"
)

func AvailableShells() []Shell {
	var shells []Shell
	for _, shell := range []Shell{ShellBash, ShellFish, ShellZsh} {
		if _, err := exec.LookPath(string(shell)); err == nil {
			shells = append(shells, shell)
		}
	}
	return shells
}

func shellCommand(shell Shell, script string) (*exec.Cmd, error) {
	switch shell {
	case ShellBash, ShellFish, ShellZsh:
		path, err := exec.LookPath(string(shell))
		if err != nil {
			return nil, fmt.Errorf("shell %q is unavailable: %w", shell, err)
		}
		return exec.Command(path, "-c", script), nil
	default:
		return nil, fmt.Errorf("unsupported shell %q", shell)
	}
}
