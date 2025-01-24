package main

import (
	"bytes"
	"embed"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// Create struct that contains the name (vuln ID), stdout, stderr, and return code DONE
//
// Import all script-maker.sh (maybe just embed now?) and iterate through them and run the script-maker.sh with go routines
//
// Collect the stdout, stderr, and exit code from the script-maker.sh and apply them to the map or slice that contains all
// the results structs

//go:embed Modules/RHEL_7/*
//go:embed Modules/RHEL_8/*
//go:embed Modules/debug/*
var testScripts embed.FS

// //go:embed testing/test.xml
// var templateFS embed.FS

type vuln struct {
	VulnHead string `xml:"ATTR_HEADER"`
	VulnID   string `xml:"PLACEHOLDER_TAG>ATTRIBUTE_DATA"`
	Details  string `xml:"FINDING_DETAILS"`
	Comments string `xml:"COMMENTS"`
	Status   string `xml:"STATUS"`
}
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

func buildScriptMap(scriptDir string) *map[string]testResult {
	scriptMap := make(map[string]testResult)

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
		scriptMap[result.vulnID] = result
	}
	return &scriptMap
}

func buildChecklist(scriptMap *map[string]testResult, benchmarkFile string, checklistFile string) error {
	fp, err := os.Open(benchmarkFile)
	if err != nil {
		fmt.Printf("Error opening benchmark file %s.\n", benchmarkFile)
		return err
	}
	defer func(fp *os.File) {
		if err := fp.Close(); err != nil {
			log.Fatal(err)
		}
	}(fp)

	var buf bytes.Buffer
	decoder := xml.NewDecoder(fp)
	encoder := xml.NewEncoder(&buf)

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error parsing token: %s\n", err.Error())
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "VULN" {
				var vuln vuln
				if err := decoder.DecodeElement(&vuln, &t); err != nil {
					log.Fatal(err)
				}
				if result, ok := (*scriptMap)[vuln.VulnID]; ok {
					switch {
					case strings.Contains(result.stdOut, "PASS"):
						vuln.Status = "PASS"
						vuln.Comments = "Verified by automation script"
						vuln.Details = result.stdOut
					case strings.Contains(result.stdOut, "FAIL"):
						vuln.Status = "FAIL"
						vuln.Comments = "Verified by automation script"
						vuln.Details = result.stdOut
					default:
						vuln.Status = "NOT_REVIEWED"
						vuln.Comments = "Script did not return expected result"
						vuln.Details = result.stdOut
					}
				} else {
					vuln.Status = "NOT_REVIEWED"
					vuln.Comments = "A script was not run for the VULN_ID"
					vuln.Details = vuln.VulnID + " MANUAL"
				}

				vuln.VulnHead = "Vuln_ID"

				if err := encoder.EncodeElement(vuln, t); err != nil {
					log.Fatal(err)
				}
				continue
			}
		}
		if err := encoder.EncodeToken(xml.CopyToken(token)); err != nil {
			log.Fatal(err)
		}
	}

	if err := encoder.Flush(); err != nil {
		log.Fatal(err)
	}

	fmt.Println(buf.String())

	checklist, err := os.Create(checklistFile)
	if err != nil {
		return err
	}
	defer func(checklist *os.File) {
		_ = checklist.Close()
	}(checklist)

	_, err = checklist.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func main() {
	debugFlag := flag.Bool("debug", false, "Enable debug mode and use specific debug script-maker.sh.")
	flag.Parse()

	var scriptDir string
	var benchmarkFile string
	var checklistFile string

	if *debugFlag {
		scriptDir = "Modules/debug"
		benchmarkFile = "testing/test.xml"
		checklistFile = "testing/checklist.ckl"
	}

	if scriptDir == "" {
		fmt.Println("Error: Script directory not specified, use -debug to troubleshoot.")
		os.Exit(1)
	}

	// Put the function call here to make it put the data in the xml format that it needs to be in
	scriptMap := buildScriptMap(scriptDir)

	err := buildChecklist(scriptMap, benchmarkFile, checklistFile)
	if err != nil {
		fmt.Println("Error building checklist:", err)
	}

	for _, result := range *scriptMap {
		fmt.Println(result.stdOut)
	}
	// Use a map of vuln structs with the ID as the key, then when decoding the XML that can be used make the process linear time instead of exponential
	// Use this blog as a reference https://penkovski.com/post/golang-update-xml-node/ I was thinking about using the "streaming" method
}
