package main

import (
	"bytes"
	"embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

// Create struct that contains the name (vuln ID), stdout, stderr, and return code DONE
//
// Import all scripts (maybe just embed now?) and iterate through them and run the scripts with go routines
//
// Collect the stdout, stderr, and exit code from the scripts and apply them to the map or slice that contains all
// the results structs

//go:embed Modules/RHEL_7/*
//go:embed Modules/RHEL_8/*
//go:embed Modules/debug/*
var testScripts embed.FS

type testResult struct {
	vulnID   string
	stdOut   string
	stdErr   string
	exitCode int
}

func executeScript(scriptDir string, scriptName string, ch chan testResult, wg *sync.WaitGroup) {
	defer wg.Done()
	cmd := exec.Command(scriptDir + "/" + scriptName)

	var vulnID string
	vulnID = scriptName[:8]

	var stdOutBuf, stdErrBuf bytes.Buffer
	cmd.Stdout = &stdOutBuf
	cmd.Stderr = &stdErrBuf

	exitCode := cmd.ProcessState.ExitCode()

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing %s: %s\n", scriptName, err.Error())
	}

	ch <- testResult{
		vulnID:   vulnID,
		stdOut:   stdOutBuf.String(),
		stdErr:   stdErrBuf.String(),
		exitCode: exitCode,
	}
}
func main() {
	debugFlag := flag.Bool("debug", false, "Enable debug mode and use specific debug scripts.")
	flag.Parse()

	var scriptDir string

	if *debugFlag {
		scriptDir = "Modules/debug"
	}

	if scriptDir == "" {
		fmt.Println("Error: Script directory not specified, use -debug to troubleshoot.")
		os.Exit(1)
	}

	testList, err := testScripts.ReadDir(scriptDir)
	if err != nil {
		panic(err)
	}

	numCPUS := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUS)

	var wg sync.WaitGroup

	resultChannel := make(chan testResult)

	for _, test := range testList {
		wg.Add(1)
		go executeScript(scriptDir, test.Name(), resultChannel, &wg)
	}

	go func() {
		wg.Wait()
		close(resultChannel)
	}()

	for result := range resultChannel {
		fmt.Printf("%+v\n", result)
	} // Put the function call here to make it put the data in the xml format that it needs to be in
}
