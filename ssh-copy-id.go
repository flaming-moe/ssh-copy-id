package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type (
	optionFlags []string

	commandLineArgs struct {
		ForceMode              bool
		DryRun                 bool
		IdentityFile           string
		KeyData                string
		Port                   int
		AlternateSshConfigFile string
		Options                optionFlags
		UserAndHostName        string
	}
)

var pCommandLineArgs *commandLineArgs

func resolvePublicData(pubIdFile string) error {
	buf, err := os.ReadFile(pubIdFile)
	if err != nil {
		return err
	}
	pCommandLineArgs.KeyData = strings.ReplaceAll(strings.ReplaceAll(string(buf), "\n", ""), "\r", "")
	return nil
}

func resolveSSHFile() error {
	if pCommandLineArgs.IdentityFile == "" {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		pCommandLineArgs.IdentityFile = filepath.Join(dirname, ".ssh", "id_rsa")
	}
	if _, err := os.Stat(pCommandLineArgs.IdentityFile); err != nil {
		return fmt.Errorf("identy file %s cannot be found", pCommandLineArgs.IdentityFile)
	}
	fileWithoutEx := strings.TrimSuffix(pCommandLineArgs.IdentityFile, filepath.Ext(pCommandLineArgs.IdentityFile))
	publicIdFile := fileWithoutEx + ".pub"
	if _, err := os.Stat(publicIdFile); err != nil {
		return fmt.Errorf("public file %s cannot be found", publicIdFile)
	}
	return resolvePublicData(publicIdFile)
}

func validateCommandLineArgs() error {
	flag.Parse()
	if flag.NArg() < 1 {
		return fmt.Errorf("you must assign a host name")
	} else if flag.NArg() > 1 {
		return fmt.Errorf("only one host name is allowed")
	}
	pCommandLineArgs.UserAndHostName = flag.Arg(0)
	return resolveSSHFile()
}

func handleOutput(w io.Writer, r io.Reader) error {
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			d := buf[:n]
			_, err := w.Write(d)
			if err != nil {
				return err
			}
		}
		if err != nil {
			// Read returns io.EOF at the end of file, which is not an error for us
			if err == io.EOF {
				err = nil
			}
			return err
		}
	}
}

func (i *optionFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *optionFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func simplifyFileName(fileName string) string {
	fName := filepath.Base(fileName)
	return strings.TrimSuffix(fName, filepath.Ext(fName))
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Description:\n\tInstall a public key in a remote machine's authorized_keys\nUsage:\n\t%s [options] [user@]hostname \nOptions:\n", simplifyFileName(os.Args[0]))
	flag.PrintDefaults()
}

func init() {
	pCommandLineArgs = new(commandLineArgs)
	flag.BoolVar(&pCommandLineArgs.ForceMode, "f", false, "Force mode -- copy keys without trying to check if they are already ")
	flag.BoolVar(&pCommandLineArgs.DryRun, "n", false, "Dry run    -- no keys are actually copied")
	flag.StringVar(&pCommandLineArgs.IdentityFile, "i", "", "Provide an optional identifile")
	flag.IntVar(&pCommandLineArgs.Port, "p", 22, "Provide a SSH port number")
	flag.StringVar(&pCommandLineArgs.AlternateSshConfigFile, "F", "", "Provide an alternative SSH configuration file")
	flag.Var(&pCommandLineArgs.Options, "o", "Provide option -- Add ssh -o options")
	flag.Usage = printUsage
}

func getCommandLineArgs() []string {
	args := make([]string, 0, 3)
	if pCommandLineArgs.Port != 22 {
		args = append(args, "-p")
		args = append(args, strconv.Itoa(pCommandLineArgs.Port))
	}

	for _, option := range pCommandLineArgs.Options {
		args = append(args, "-o")
		args = append(args, option)
	}
	args = append(args, pCommandLineArgs.UserAndHostName)
	return args
}

func runSSHExec(command string) (int, error) {
	args := append(getCommandLineArgs(), command)
	cmd := exec.Command("ssh", args...)
	var errStdout, errStderr error

	stdoutIn, _ := cmd.StdoutPipe()
	stderrIn, _ := cmd.StderrPipe()
	err := cmd.Start()
	if err != nil {
		return 1, fmt.Errorf("cmd.Start() failed with '%s'", err)
	}
	// cmd.Wait() should be called only after we finish reading
	// from stdoutIn and stderrIn.
	// wg ensures that we finish
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		errStdout = handleOutput(os.Stdout, stdoutIn)
		wg.Done()
	}()

	errStderr = handleOutput(os.Stderr, stderrIn)

	wg.Wait()

	if errStdout != nil || errStderr != nil {
		return 1, fmt.Errorf("failed to capture stdout or stderr")
	}

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			return exiterr.ExitCode(), err
		} else {
			return 1, fmt.Errorf("cmd.Wait: %v", err)
		}
	}
	ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
	return ws.ExitStatus(), err
}

func main() {

	if err := validateCommandLineArgs(); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing command line arguments:\n\t\033[31m%v\033[0m\n", err.Error())
		printUsage()
		os.Exit(1)
	}

	var command string
	if !pCommandLineArgs.ForceMode {
		command = fmt.Sprintf("if [[ ! -e ~/.ssh/authorized_keys ]]; then mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys; fi; if  grep -q '%s' ~/.ssh/authorized_keys;then exit 201;else echo '%s' >> ~/.ssh/authorized_keys;fi", pCommandLineArgs.KeyData, pCommandLineArgs.KeyData)
	} else {
		command = fmt.Sprintf("mkdir -p \"~/.ssh\"; echo '%s' >> ~/.ssh/authorized_keys", pCommandLineArgs.KeyData)
	}

	exitCode, err := runSSHExec(command)
	if exitCode == 201 {
		fmt.Fprintf(os.Stderr, "Error execution command:\n\t\n\033[31mPublic key data '%s' already exists in authorized_keys.\033[0m\n\n", pCommandLineArgs.KeyData)
		os.Exit(exitCode)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "Error adding key.Reason: %v", err)
		if exitCode != 0 {
			os.Exit(exitCode)
		} else {
			os.Exit(1)
		}
	}
}
