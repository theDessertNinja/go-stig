package main

import (
	"bytes"
	"embed"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// Create struct that contains the name (vuln ID), stdout, stderr, and return code DONE
//
// Import all scripts (maybe just embed now?) and iterate through them and run the scripts with go routines
//
// Collect the stdout, stderr, and exit code from the scripts and apply them to the map or slice that contains all
// the results structs

//go:embed Modules/RHEL_7
//go:embed Modules/RHEL_8
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
	cmd := exec.Command(scriptDir + scriptName)

	var vulnID string
	vulnID = scriptName

	var stdOutBuf, stdErrBuf bytes.Buffer
	cmd.Stdout = &stdOutBuf
	cmd.Stderr = &stdErrBuf

	exitCode := cmd.ProcessState.ExitCode()

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing testScripts/%s: %s\n", scriptName, err.Error())
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
	var osReleaseBuf bytes.Buffer
	exec.Command("bash", "-c", "source /etc/os-release && echo $VERSION_ID").Stdout = &osReleaseBuf

	osRelease := osReleaseBuf.String()

	var scriptDir string

	if strings.Contains(osRelease, "7.") {
		scriptDir = "Modules/RHEL_7"
	} else if strings.Contains(osRelease, "8.") {
		scriptDir = "Modules/RHEL_8"
	} else {
		fmt.Printf("This program only supports RHEL 7 and RHEL 8.\n")
		//os.Exit(0)
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
