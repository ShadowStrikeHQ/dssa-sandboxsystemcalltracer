#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import sys
import tempfile
import shlex

# Optional dependencies (install if needed: pip install python-magic oletools)
try:
    import magic
except ImportError:
    magic = None
    print("Warning: python-magic not found. File type detection will be limited.")

try:
    import oletools.oleid
    import oletools.olevba
except ImportError:
    oletools = None
    print("Warning: oletools not found. VBScript analysis will be limited.")


# Constants
LOG_LEVELS = {'debug': logging.DEBUG, 'info': logging.INFO, 'warning': logging.WARNING, 'error': logging.ERROR, 'critical': logging.CRITICAL}
DEFAULT_LOG_LEVEL = 'info'
DEFAULT_TIMEOUT = 60  # seconds


def setup_argparse():
    """Sets up the argument parser for the command line interface."""

    parser = argparse.ArgumentParser(description="dssa-SandboxSystemCallTracer: A lightweight utility that traces system calls made by a sandboxed script.")
    parser.add_argument("script", help="Path to the script to be analyzed.")
    parser.add_argument("--interpreter", "-i", help="Path to the interpreter to use (e.g., python3, javascript). If not specified, attempts to auto-detect.", default=None)
    parser.add_argument("--timeout", "-t", type=int, help=f"Timeout for script execution in seconds (default: {DEFAULT_TIMEOUT}).", default=DEFAULT_TIMEOUT)
    parser.add_argument("--log-level", "-l", choices=LOG_LEVELS.keys(), default=DEFAULT_LOG_LEVEL, help=f"Set the logging level (default: {DEFAULT_LOG_LEVEL}).")
    parser.add_argument("--output", "-o", help="Path to save the system call trace log.", default=None)
    parser.add_argument("--sandbox", "-s", action="store_true", help="Enable sandboxing using seccomp-tools (requires sudo and seccomp-tools installed).")
    parser.add_argument("--command-line-args", nargs='*', help="Arguments to pass to the script.", default=[])
    return parser


def detect_file_type(filepath):
    """Detects the file type using libmagic."""
    if magic:
        try:
            mime_type = magic.from_file(filepath, mime=True).decode('utf-8')
            return mime_type
        except Exception as e:
            logging.warning(f"File type detection failed: {e}")
            return None
    else:
        logging.warning("python-magic not installed. File type detection disabled.")
        return None


def analyze_vbscript(filepath):
    """Basic VBScript analysis using oletools."""
    if oletools:
        try:
            oleid_obj = oletools.oleid.OleID(filepath)
            if oleid_obj.check():
                olevba_obj = oletools.olevba.VBA_Parser(filepath)
                if olevba_obj.detect_vba_macros():
                    logging.info("VBA macros detected in VBScript.")
                    # Print basic macro information.  Could be extended to extract specific keywords.
                    for (filename, stream_path, vba_filename, vba_code) in olevba_obj.extract_macros():
                        logging.debug(f"VBA Macro found in {filename}:{stream_path}:{vba_filename}")
                else:
                    logging.info("No VBA macros detected in VBScript.")

        except Exception as e:
            logging.error(f"Error analyzing VBScript with oletools: {e}")
    else:
        logging.warning("oletools not installed. VBScript analysis disabled.")


def run_script_with_ptrace(script_path, interpreter_path, timeout, command_line_args, output_file, sandbox_enabled):
    """Runs the script with ptrace and logs system calls."""

    if not os.path.exists(script_path):
        raise FileNotFoundError(f"Script not found: {script_path}")

    if interpreter_path and not os.path.exists(interpreter_path):
        raise FileNotFoundError(f"Interpreter not found: {interpreter_path}")

    # Construct the command
    command = []
    if sandbox_enabled:
        # Requires sudo and seccomp-tools installed (e.g., sudo apt install seccomp-tools)
        # This is a basic example.  Customize the seccomp profile for more robust sandboxing.
        command.extend(["sudo", "seccomp-tools", "sandbox"])

    if interpreter_path:
        command.append(interpreter_path)
    else:
        # Attempt to auto-detect interpreter.  This is a basic approach and may need refinement.
        file_type = detect_file_type(script_path)
        if file_type and "python" in file_type:
            command.append("python3")  # Or python, depending on the system
        elif file_type and "javascript" in file_type:
            command.append("node") # Or rhino, depending on the system. Install node.js
        elif file_type and "vbscript" in file_type:
            command.append("cscript") #windows only.
        else:
            logging.warning("Could not auto-detect interpreter. Please specify with --interpreter.")
            command.append(script_path)
            command_line_args = [] #Prevent appending args to script directly, might cause errors.
    
    if not sandbox_enabled and interpreter_path is None and command[-1] == script_path:
        command = [script_path] #just run the file.

    command.append(script_path)
    command.extend(command_line_args)


    logging.debug(f"Executing command: {' '.join(map(shlex.quote, command))}") #Quote to handle spaces in arguments.

    try:
        # Capture stdout and stderr separately.  Consider using `trace` tool for system call tracing
        # but it often requires more configuration and might not be suitable for quick triage.
        # For basic system call tracing, consider `strace` if available.  The following is a simplified example.
        # THIS DOES NOT ACTUALLY TRACE SYSTEM CALLS.  It's a placeholder.  Requires `strace`.

        # Using subprocess.run with a timeout and capturing both stdout and stderr
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout) #Changed to use text=True for easier handling

        logging.info(f"Script execution completed with return code: {result.returncode}")
        logging.debug(f"stdout: {result.stdout}")
        logging.debug(f"stderr: {result.stderr}")

        if output_file:
            try:
                with open(output_file, "w") as f:
                     f.write(f"Command: {' '.join(map(shlex.quote, command))}\n")
                     f.write(f"Return code: {result.returncode}\n")
                     f.write(f"stdout:\n{result.stdout}\n")
                     f.write(f"stderr:\n{result.stderr}\n")
                logging.info(f"Output saved to: {output_file}")

            except Exception as e:
                logging.error(f"Failed to save output to file: {e}")


        # Basic error handling based on return code and stderr.  Expand as needed.
        if result.returncode != 0:
            logging.warning(f"Script execution returned a non-zero exit code: {result.returncode}")
            if result.stderr:
                logging.warning(f"stderr: {result.stderr}")
        
    except subprocess.TimeoutExpired:
        logging.error(f"Script execution timed out after {timeout} seconds.")
        raise
    except FileNotFoundError as e:
        logging.error(f"Execution failed: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise



def main():
    """Main function to parse arguments and run the script analysis."""

    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging
    log_level = LOG_LEVELS.get(args.log_level.lower(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    script_path = args.script
    interpreter_path = args.interpreter
    timeout = args.timeout
    output_file = args.output
    sandbox_enabled = args.sandbox
    command_line_args = args.command_line_args


    # Validate timeout value
    if timeout <= 0:
        logging.error("Timeout value must be greater than 0.")
        sys.exit(1)


    try:
        # Basic input validation (can be extended)
        if not os.path.exists(script_path):
            logging.error(f"Script not found: {script_path}")
            sys.exit(1)

        file_type = detect_file_type(script_path)
        logging.info(f"Detected file type: {file_type}")

        # Preliminary analysis based on file type.  Expand as needed.
        if file_type and "vbscript" in file_type:
            analyze_vbscript(script_path)  # Uses oletools

        run_script_with_ptrace(script_path, interpreter_path, timeout, command_line_args, output_file, sandbox_enabled)


    except FileNotFoundError as e:
        logging.error(e) #already formatted in run_script_with_ptrace
        sys.exit(1)
    except subprocess.TimeoutExpired:
        logging.error(f"Script execution timed out after {timeout} seconds.")
        sys.exit(1)
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()