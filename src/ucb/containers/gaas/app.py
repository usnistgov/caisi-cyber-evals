#!/usr/bin/env python3
import os
import hashlib
import logging
import time
from typing import Tuple, List, Set, Dict
from functools import lru_cache
from flask import Flask, request, jsonify, abort

import pyghidra

pyghidra.start()
import ghidra
from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.util.task import TaskMonitor

"""
Web app to allow a user to upload a binary then run ghidra based analyses on it
Binaries are cached by their hash, analyses are keyed on hash and cached
"""

VERSION = 1.0

# Create and configure Flask app.
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GhidraServiceApp")

# Configuration constants.
BINARY_CACHE_DIR = "cache/binaries"
GHIDRA_PROJ_DIR = "cache/ghidra"
os.makedirs(BINARY_CACHE_DIR, exist_ok=True)
os.makedirs(GHIDRA_PROJ_DIR, exist_ok=True)


def error(error_msg: str):
    return jsonify({"message": error_msg}), 400


def compute_hash(file_bytes: bytes) -> str:
    """
    Compute a SHA256 hash for the given file bytes.
    """
    sha = hashlib.sha256()
    sha.update(file_bytes)
    return sha.hexdigest()


class GhidraService:
    """
    Encapsulates Ghidra-based analyses functionality.
    """

    @staticmethod
    @lru_cache(maxsize=50)
    def get_functions(binary_hash: str) -> Tuple[List, int]:
        """
        Open the binary via pyghidra, extract function names (excluding default FUN_ names),
        and return a list of named functions paired with a count of unnamed functions
        """
        binary_path = os.path.join(BINARY_CACHE_DIR, binary_hash)
        if not os.path.exists(binary_path):
            logger.error("Binary not found in cache: %s", binary_hash)
            raise FileNotFoundError("Binary not found in cache.")

        results = []
        unnamed_funcs = set()
        # Open the program with pyghidra and iterate over functions:
        start = time.time()
        with pyghidra.open_program(
            binary_path, project_name=binary_hash, project_location=GHIDRA_PROJ_DIR
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            for func in program.functionManager.getFunctions(True):
                func_name = func.getName()
                # Filter out automatically generated names
                if func_name.startswith("FUN_"):
                    unnamed_funcs.add(func_name)
                else:
                    results.append(func_name)
        duration = time.time() - start
        logger.info("Function listing for %s took %.02f seconds", binary_hash, duration)

        return " ".join(results), len(unnamed_funcs)

    @staticmethod
    def find_function_by_name(program, function_name: str):
        for func in program.functionManager.getFunctions(True):
            if func.getName() == function_name:
                return func
        return None

    @staticmethod
    @lru_cache(maxsize=50)
    def decompile(binary_hash: str, func_name: str) -> str:
        """
        Open the binary via pyghidra and decompile the specified function
        """
        binary_path = os.path.join(BINARY_CACHE_DIR, binary_hash)
        if not os.path.exists(binary_path):
            logger.error("Binary not found in cache: %s", binary_hash)
            raise FileNotFoundError("Binary not found in cache.")

        start = time.time()
        with pyghidra.open_program(
            binary_path, project_name=binary_hash, project_location=GHIDRA_PROJ_DIR
        ) as flat_api:
            program = flat_api.getCurrentProgram()

            target_func = GhidraService.find_function_by_name(program, func_name)
            if target_func is None:
                raise NameError(f"Function {func_name} not found.")

            decomp_api = FlatDecompilerAPI(flat_api)
            result = decomp_api.decompile(target_func)
            decomp_api.dispose()  # XXX ???
        duration = time.time() - start
        logger.info("Decompilation for %s took %.02f seconds", binary_hash, duration)

        return result

    @staticmethod
    @lru_cache(maxsize=50)
    def disassemble(binary_hash: str, func_name: str) -> str:
        """
        Open the binary via pyghidra and disassemble the specified function,
        returning the disassembly text.
        """
        binary_path = os.path.join(BINARY_CACHE_DIR, binary_hash)
        if not os.path.exists(binary_path):
            logger.error("Binary not found in cache: %s", binary_hash)
            raise FileNotFoundError(f"Binary {binary_hash} not found in cache.")

        start = time.time()

        with pyghidra.open_program(
            binary_path, project_name=binary_hash, project_location=GHIDRA_PROJ_DIR
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            target_func = GhidraService.find_function_by_name(program, func_name)
            if target_func is None:
                raise NameError(
                    f"Function {func_name} not found in binary {binary_hash}."
                )

            # Grab function boundaries
            func_body = target_func.getBody()
            listing = program.getListing()

            # Iterate over instructions to generate disassembly output
            instructions = listing.getInstructions(func_body, True)
            disassembly_lines = []
            for instruction in instructions:
                address = instruction.getAddress()
                mnemonic = instruction.getMnemonicString()
                num_operands = instruction.getNumOperands()
                operands = []
                for op_idx in range(num_operands):
                    # Carefully iterate over operands and stringify
                    operand_repr_objs = instruction.getDefaultOperandRepresentationList(
                        op_idx
                    )
                    if operand_repr_objs is None:
                        continue  # language may not support operand representation
                    operand_text = "".join(str(obj) for obj in operand_repr_objs)
                    operands.append(operand_text)

                operand_str = ", ".join(operands)
                line = f"{address}: {mnemonic} {operand_str}".strip()
                disassembly_lines.append(line)

        duration = time.time() - start
        logger.info(
            "Disassembly of function '%s' for binary %s took %.02f seconds",
            func_name,
            binary_hash,
            duration,
        )
        return disassembly_lines

    @staticmethod
    def _build_caller_tree(program, target_func, level: int, visited: Set) -> Dict:
        """
        Recursively build a caller tree for target_func up to a given level.
        The tree node for a function will have:
            { "name": <function_name>, "callers": [ ... ] }
        where "callers" are the functions that call the current function.
        """
        func_id = target_func.getEntryPoint().toString()
        if func_id in visited:
            return {"name": target_func.getName(), "callers": []}

        visited.add(func_id)
        if level <= 0:
            return {"name": target_func.getName(), "callers": []}

        tree = {"name": target_func.getName(), "callers": []}
        monitor = TaskMonitor.DUMMY
        for caller in target_func.getCallingFunctions(monitor):
            subtree = GhidraService._build_caller_tree(
                program, caller, level - 1, visited
            )
            tree["callers"].append(subtree)
        return tree

    @staticmethod
    def _build_callee_tree(program, target_func, level: int, visited: Set) -> Dict:
        """
        Recursively build a callee tree for target_func up to a given level.
        """
        func_id = target_func.getEntryPoint().toString()
        if func_id in visited:
            return {"name": target_func.getName(), "children": []}

        visited.add(func_id)
        if level <= 0:
            return {"name": target_func.getName(), "children": []}

        tree = {"name": target_func.getName(), "children": []}
        monitor = TaskMonitor.DUMMY
        for callee in target_func.getCalledFunctions(monitor):
            subtree = GhidraService._build_callee_tree(
                program, callee, level - 1, visited
            )
            tree["children"].append(subtree)
        return tree

    @staticmethod
    @lru_cache(maxsize=50)
    def get_caller_tree(binary_hash: str, func_name: str, levels: int = 2) -> Dict:
        """
        Open the binary via pyghidra and build a caller tree for the specified function
        up to N levels deep, where each node's "callers" field represents the functions
        that call it.
        """
        binary_path = os.path.join(BINARY_CACHE_DIR, binary_hash)
        if not os.path.exists(binary_path):
            logger.error("Binary not found in cache: %s", binary_hash)
            raise FileNotFoundError(f"Binary {binary_hash} not found in cache.")

        start = time.time()
        with pyghidra.open_program(
            binary_path, project_name=binary_hash, project_location=GHIDRA_PROJ_DIR
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            target_func = GhidraService.find_function_by_name(program, func_name)
            if target_func is None:
                raise NameError(
                    f"Function {func_name} not found in binary {binary_hash}."
                )

            # Build caller tree recursively.
            tree = GhidraService._build_caller_tree(
                program, target_func, levels, visited=set()
            )

        duration = time.time() - start
        logger.info(
            "Caller tree for function '%s' in binary %s with depth %d took %.02f seconds",
            func_name,
            binary_hash,
            levels,
            duration,
        )
        return tree

    @staticmethod
    @lru_cache(maxsize=50)
    def get_callee_tree(binary_hash: str, func_name: str, levels: int = 2) -> Dict:
        """
        Open the binary via pyghidra and build a callee tree for the specified function
        up to N levels deep.

        Args:
            binary_hash (str): The hash of the cached binary.
            func_name (str): The name of the target function.
            levels (int): Number of callee levels to traverse (default: 2).

        Returns:
            Dict: A tree where each node is in the form:
                  {"name": <function_name>, "children": [ ... ] }
        """
        binary_path = os.path.join(BINARY_CACHE_DIR, binary_hash)
        if not os.path.exists(binary_path):
            logger.error("Binary not found in cache: %s", binary_hash)
            raise FileNotFoundError(f"Binary {binary_hash} not found in cache.")

        start = time.time()
        with pyghidra.open_program(
            binary_path, project_name=binary_hash, project_location=GHIDRA_PROJ_DIR
        ) as flat_api:
            program = flat_api.getCurrentProgram()
            target_func = GhidraService.find_function_by_name(program, func_name)
            if target_func is None:
                raise NameError(
                    f"Function {func_name} not found in binary {binary_hash}."
                )

            tree = GhidraService._build_callee_tree(
                program, target_func, levels, visited=set()
            )

        duration = time.time() - start
        logger.info(
            "Callee tree for function '%s' in binary %s with depth %d took %.02f seconds",
            func_name,
            binary_hash,
            levels,
            duration,
        )
        return tree


# Routes
@app.route("/")
def home():
    return jsonify({"version": VERSION})


@app.route("/check", methods=["POST"])
def check():
    """
    Check if a binary with the supplied hash exists in the cache.
    Request form must include: binary_hash
    Returns JSON in the format: {"hit": bool}
    """
    binary_hash = request.form.get("binary_hash")
    if not binary_hash:
        return error("Binary hash must be provided.")
    binary_path = os.path.join(BINARY_CACHE_DIR, binary_hash)
    hit = os.path.exists(binary_path)
    return jsonify({"hit": hit})


@app.route("/upload", methods=["POST"])
def upload():
    """
    Upload a new binary file.
    Request must include a file field named 'binary'.
    Returns JSON in the format: {"key": <binary_hash>}
    """
    if "binary" not in request.files:
        return error("No binary file provided.")
    file_storage = request.files["binary"]
    file_bytes = file_storage.read()
    binary_hash = compute_hash(file_bytes)
    binary_path = os.path.join(BINARY_CACHE_DIR, binary_hash)

    if not os.path.exists(binary_path):
        with open(binary_path, "wb") as f:
            f.write(file_bytes)
        logger.info("Uploaded and cached new binary with hash: %s", binary_hash)
    else:
        logger.info("Binary already exists in cache: %s", binary_hash)
    return jsonify({"key": binary_hash})


@app.route("/list_functions", methods=["POST"])
def list_functions():
    """
    List named functions for a previously uploaded binary.
    Expects binary_hash in the request form.
    Returns JSON in the format: {"functions": [...]}
    """
    binary_hash = request.form.get("binary_hash")
    if not binary_hash:
        return error("Binary hash must be provided.")
    try:
        functions, num_unnamed = GhidraService.get_functions(binary_hash)
    except FileNotFoundError:
        return error("Binary not found in cache. Please upload the binary first.")
    return jsonify(
        {"named_functions": functions, "unnamed_function_count": num_unnamed}
    )


@app.route("/decompile", methods=["POST"])
def decompile():
    """
    Decompile a function for a previously uploaded binary.
    Expects binary_hash in the request form.
    Returns JSON in the format: {"decompilation": [...]}
    """
    binary_hash = request.form.get("binary_hash")
    if not binary_hash:
        return error("Binary hash must be provided.")
    function_name = request.form.get("function_name")
    if not function_name:
        return error("Function name must be provided.")
    try:
        decomp = GhidraService.decompile(binary_hash, function_name)
    except FileNotFoundError:
        return error("Binary not found in cache. Please upload the binary first.")
    except NameError:
        return error("Function name not present in binary")
    return jsonify({"decompilation": decomp})


@app.route("/disassemble", methods=["POST"])
def disassemble():
    """
    Disassemble a function for a previously uploaded binary.
    Expects binary_hash in the request form.
    Returns JSON in the format: {"disassembly": [line1, line2, ...]}
    """
    binary_hash = request.form.get("binary_hash")
    if not binary_hash:
        return error("Binary hash must be provided.")
    function_name = request.form.get("function_name")
    if not function_name:
        return error("Function name must be provided.")
    try:
        decomp = GhidraService.disassemble(binary_hash, function_name)
    except FileNotFoundError:
        return error("Binary not found in cache. Please upload the binary first.")
    except NameError:
        return error("Function name not present in binary")
    return jsonify({"disassembly": decomp})


@app.route("/callers", methods=["POST"])
def callers():
    """
    Get callers of a function for a previously uploaded binary.
    Expects binary_hash in the request form.
    Returns JSON in the format: {"callers": [name1, name2, ...]}
    """
    depth = int(request.form.get("depth", 1))
    binary_hash = request.form.get("binary_hash")
    if not binary_hash:
        return error("Binary hash must be provided.")
    function_name = request.form.get("function_name")
    if not function_name:
        return error("Function name must be provided.")
    try:
        callers = GhidraService.get_caller_tree(
            binary_hash, function_name, levels=depth
        )
    except FileNotFoundError:
        return error("Binary not found in cache. Please upload the binary first.")
    except NameError:
        return error("Function name not present in binary")
    return jsonify({"callers": callers})


@app.route("/callees", methods=["POST"])
def callees():
    """
    Get calles of a function for a previously uploaded binary.
    Expects binary_hash in the request form.
    Returns JSON in the format: {"callers": [name1, name2, ...]}
    """
    depth = int(request.form.get("depth", 1))
    binary_hash = request.form.get("binary_hash")
    if not binary_hash:
        return error("Binary hash must be provided.")
    function_name = request.form.get("function_name")
    if not function_name:
        return error("Function name must be provided.")
    try:
        callees = GhidraService.get_callee_tree(
            binary_hash, function_name, levels=depth
        )
    except FileNotFoundError:
        return error("Binary not found in cache. Please upload the binary first.")
    except NameError:
        return error("Function name not present in binary")
    return jsonify({"callees": callees})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
