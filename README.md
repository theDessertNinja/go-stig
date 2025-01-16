# go-stig
This repository will contain the prototype for the rewrite of the RHEL STIG script that my team uses.

That tool is currently written in python and executes all of the vuln checks through simple bash scripts that output
their findings to `stdout`. This is then taken and aggregated into a modified version of the benchmark `.ckl` file.

The goal of this project is to greatly speed up the testing through multithreading, and allowing the test to be run
without python being installed (or literally anything other than bash). There are a few long term goals I have like providing  `.rpm` releases directly to 
satellite and creating a server application to control the stig checks from a centralized location.