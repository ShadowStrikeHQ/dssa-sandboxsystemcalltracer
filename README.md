# dssa-SandboxSystemCallTracer
A lightweight utility that traces system calls made by a sandboxed script using `ptrace` or `seccomp-tools`, logging the call number, arguments, and return value to identify suspicious behavior or resource access. - Focused on Performs basic dynamic analysis of scripts (e.g., Python, JavaScript, VBScript) in a sandboxed environment.  Focuses on identifying potentially malicious behaviors like file system modifications, network connections, and registry access by extracting events triggered during execution. Aims for minimal overhead and quick triage.

## Install
`git clone https://github.com/ShadowStrikeHQ/dssa-sandboxsystemcalltracer`

## Usage
`./dssa-sandboxsystemcalltracer [params]`

## Parameters
- `-h`: Show help message and exit
- `--interpreter`: No description provided
- `--timeout`: No description provided
- `--log-level`: No description provided
- `--output`: Path to save the system call trace log.
- `--sandbox`: No description provided
- `--command-line-args`: Arguments to pass to the script.

## License
Copyright (c) ShadowStrikeHQ
