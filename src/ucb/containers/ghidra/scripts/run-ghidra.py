#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile


def execute_ghidra(process, binary_filepath, output_path):
    post_script = (
        "DisassembleToJson.java" if process == "disassemble" else "DecompileToJson.java"
    )
    with tempfile.TemporaryDirectory() as temp_project_dir:
        try:
            subprocess.run(
                [
                    os.environ["GHIDRA_HEADLESS"],
                    temp_project_dir,
                    "dummy_project_name",
                    "-import",
                    binary_filepath,
                    "-scriptPath",
                    os.environ["GHIDRA_SCRIPTS"],
                    "-postScript",
                    post_script,
                    output_path,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"Ghidra error: {e.stderr.decode()}")
            sys.exit(1)


def extract_function(output_path, function_name):
    with open(output_path) as f:
        data = json.load(f)
    if result := data.get(function_name):
        return result
    # If the requested function name is "main" but doesn't exist, and the binary has a
    # "_start" function, return it.
    if function_name == "main" and (result := data.get("_start")):
        return result
    # Function not found return list of functions
    return f"Function not found, these are the functions {data.keys()}"


def get_args():
    if len(sys.argv) != 4:
        script_name = os.path.basename(__file__)
        print(
            f"Usage: {script_name} <decompile|disassemble> <binary_path> "
            "<function_name>"
        )
        sys.exit(1)
    process = sys.argv[1]
    if process not in ["decompile", "disassemble"]:
        print(f"Error: unknown argument {process} expected decompile or disassemble")
        sys.exit(1)
    binary_path = sys.argv[2]
    if not os.path.exists(binary_path):
        print(f"Error: binary {binary_path} not found")
        sys.exit(1)
    return process, binary_path, sys.argv[3]


def main():
    process, binary_path, function_name = get_args()
    if not os.path.isfile(binary_path):
        print(f"Error: binary {binary_path} not found")
        sys.exit(1)
    with tempfile.TemporaryDirectory() as temp_output_dir:
        output_path = os.path.join(temp_output_dir, "output.json")
        execute_ghidra(process, binary_path, output_path)
        function = extract_function(output_path, function_name)
    if function:
        print(function)
    else:
        print(f"Error: function {function_name} not found in {binary_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
