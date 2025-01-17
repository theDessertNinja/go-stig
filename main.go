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

type job struct {
	index int
	vuln  string
}

func executeScript(scriptDir string, scriptName string) testResult {
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
		return testResult{vulnID, stdOutBuf.String(), stdErrBuf.String(), exitCode}
	}

	return testResult{
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

	// Go routines here that call the execute function with the file name
	numCPUS := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUS)

	var wg sync.WaitGroup
	testResults := make([]testResult, len(testList))
	jobs := make(chan job, len(testList))

	for w := 0; w < numCPUS; w++ {
		go func() {
			for job := range jobs {
				testResults[job.index] = executeScript(scriptDir, job.vuln)
				wg.Done()
			}
		}()
	}

	wg.Add(len(testList))
	for i, test := range testList {
		jobs <- job{i, test.Name()}
	}

	close(jobs)
	wg.Wait()

	for _, result := range testResults {
		fmt.Printf("%+v\n", result)
	} // Put the function call here to make it put the data in the xml format that it needs to be in
}
