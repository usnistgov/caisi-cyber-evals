import hashlib
import requests
from typing import List


class GhidraClient:
    """
    A small client interface to interact with the Ghidra webapp.
    Endpoints supported:
      - /check: Check if a binary exists in the cache.
      - /upload: Upload a binary file.
      - /list_functions: List functions from a binary.
      - /decompile: Get the decompilation of a function.
      - /disassemble: Get the disassembly of a function.
    """

    def __init__(self, base_url: str):
        # Remove any trailing slash from base_url.
        self.base_url = base_url.rstrip("/")
        self.gaas_alive = False

    def check_online(self):
        if self.gaas_alive:
            return

        try:
            response = requests.get(self.base_url)
            # Confirm server is reachable
            response.raise_for_status()
        except requests.exceptions.ConnectionError:
            raise ValueError(
                f"Ghidra server is unreachable at {self.base_url}. Do you need to start GaaS?"
            )
        data = response.json()
        # Confirm version is supported
        version = data.get("version", "unspecified")
        if version != 1.0:
            raise ValueError(
                f"GaaS at {self.base_url} running unsupported version {version}"
            )

        self.gaas_alive = True

    def compute_hash(self, file_bytes: bytes) -> str:
        """
        Compute a SHA256 hash for the given file bytes.
        """
        sha = hashlib.sha256()
        sha.update(file_bytes)
        return sha.hexdigest()

    def check_and_upload(self, binary: bytes) -> str:
        """
        Given a binary, compute its hash and check if it's present
        on the server. If not upload it.

        Raises an exception onf ailure
        """
        binary_hash = self.compute_hash(binary)
        if not self.check(binary_hash):
            # Not present, upload it
            self.upload(binary)
        return binary_hash

    def check(self, binary_hash: str) -> bool:
        """
        Check if the binary with the given hash exists.
        Returns True if found; False if not.
        """
        url = f"{self.base_url}/check"
        response = requests.post(url, data={"binary_hash": binary_hash})
        try:
            response.raise_for_status()
            data = response.json()
            return data.get("hit", False)
        except requests.exceptions.HTTPError:
            # Attempt to extract error message from the JSON response
            try:
                error_data = response.json()
                error_message = error_data.get("message")
            except ValueError:
                # In case the response is not JSON formatted, fallback to response text
                error_message = response.text

            # Return or handle the error message
            return f"Error with request: {error_message}"

    def upload(self, binary: bytes) -> str:
        """
        Upload a binary file from the given path.
        Returns the binary hash (key) returned by the webapp.
        """
        self.check_online()
        url = f"{self.base_url}/upload"
        files = {"binary": binary}
        response = requests.post(url, files=files)
        try:
            response.raise_for_status()
            data = response.json()
            return data.get("key")
        except requests.exceptions.HTTPError:
            # Attempt to extract error message from the JSON response
            try:
                error_data = response.json()
                error_message = error_data.get("message")
            except ValueError:
                # In case the response is not JSON formatted, fallback to response text
                error_message = response.text

            # Return or handle the error message
            return f"Error with request: {error_message}"

    def list_functions(self, binary: bytes) -> List[str]:
        """
        List functions for a given binary.
        Returns list of named functions
        """
        self.check_online()
        url = f"{self.base_url}/list_functions"
        binary_hash = self.check_and_upload(binary)
        response = requests.post(url, data={"binary_hash": binary_hash})
        try:
            response.raise_for_status()
            data = response.json()
            return data.get("named_functions")
        except requests.exceptions.HTTPError:
            # Attempt to extract error message from the JSON response
            try:
                error_data = response.json()
                error_message = error_data.get("message")
            except ValueError:
                # In case the response is not JSON formatted, fallback to response text
                error_message = response.text

            # Return or handle the error message
            return f"Error with request: {error_message}"

    def decompile(self, binary: bytes, function_name: str) -> str:
        """
        Request the decompilation of a specified function.
        Returns the decompilation as provided by the webapp.
        """
        self.check_online()
        url = f"{self.base_url}/decompile"
        binary_hash = self.check_and_upload(binary)
        response = requests.post(
            url, data={"binary_hash": binary_hash, "function_name": function_name}
        )
        try:
            response.raise_for_status()
            data = response.json()
            return data.get("decompilation")
        except requests.exceptions.HTTPError:
            # Attempt to extract error message from the JSON response
            try:
                error_data = response.json()
                error_message = error_data.get("message")
            except ValueError:
                # In case the response is not JSON formatted, fallback to response text
                error_message = response.text

            # Return or handle the error message
            return f"Error with request: {error_message}"

    def disassemble(self, binary: bytes, function_name: str) -> str:
        """
        Request the disassembly of a specified function.
        Returns the disassembly (likely as a list of lines) provided by the webapp.
        """
        self.check_online()
        url = f"{self.base_url}/disassemble"
        binary_hash = self.check_and_upload(binary)
        response = requests.post(
            url, data={"binary_hash": binary_hash, "function_name": function_name}
        )
        try:
            response.raise_for_status()
            data = response.json()
            return data.get("disassembly")
        except requests.exceptions.HTTPError:
            # Attempt to extract error message from the JSON response
            try:
                error_data = response.json()
                error_message = error_data.get("message")
            except ValueError:
                # In case the response is not JSON formatted, fallback to response text
                error_message = response.text

            # Return or handle the error message
            return f"Error with request: {error_message}"

    def get_callers(self, binary: bytes, function_name: str, depth: int) -> list[str]:
        """
        Request the callers of a specified function.
        Returns a list of callers
        """
        self.check_online()
        url = f"{self.base_url}/callers"
        binary_hash = self.check_and_upload(binary)
        response = requests.post(
            url,
            data={
                "binary_hash": binary_hash,
                "function_name": function_name,
                "depth": depth,
            },
        )
        try:
            response.raise_for_status()
            data = response.json()
            return data.get("callers")
        except requests.exceptions.HTTPError:
            # Attempt to extract error message from the JSON response
            try:
                error_data = response.json()
                error_message = error_data.get("message")
            except ValueError:
                # In case the response is not JSON formatted, fallback to response text
                error_message = response.text

            # Return or handle the error message
            return f"Error with request: {error_message}"

    def get_callees(self, binary: bytes, function_name: str, depth: int):
        """
        Request the callees of a specified function.
        Returns a list of callees
        """
        self.check_online()
        url = f"{self.base_url}/callees"
        binary_hash = self.check_and_upload(binary)
        response = requests.post(
            url,
            data={
                "binary_hash": binary_hash,
                "function_name": function_name,
                "depth": depth,
            },
        )
        try:
            response.raise_for_status()
            data = response.json()
            return data.get("callees")
        except requests.exceptions.HTTPError:
            # Attempt to extract error message from the JSON response
            try:
                error_data = response.json()
                error_message = error_data.get("message")
            except ValueError:
                # In case the response is not JSON formatted, fallback to response text
                error_message = response.text

            # Return or handle the error message
            return f"Error with request: {error_message}"
