"""
Secure string implementation for memory-safe secret storage.

Provides SecureString class that:
- Duck-types as a string (works in most string contexts)
- Stores data in ctypes-controlled memory (not GC-managed)
- Has explicit eradicate() method that overwrites with random bytes
- Raises errors if accessed after eradication
"""
import ctypes
import os
import warnings
from typing import Any


class SecureStringEradicated(Exception):
    """Raised when accessing an eradicated SecureString."""
    pass


class SecureString:
    """
    A string-like object that stores secrets in controlled memory.

    Unlike Python strings, SecureString:
    - Stores data in ctypes-allocated memory (not GC-managed)
    - Can be explicitly eradicated (overwritten with random bytes)
    - Raises errors if accessed after eradication

    Usage:
        password = SecureString(getpass.getpass())
        # ... use password ...
        password.eradicate()  # Overwrites memory with random bytes

    Note: The original string passed to __init__ is still in Python's
    memory. For maximum security, read secrets directly into SecureString
    or ensure the source is short-lived.
    """

    __slots__ = ('_buffer', '_length', '_eradicated')

    def __init__(self, value: str | bytes):
        """
        Create a SecureString from a string or bytes.

        Args:
            value: The secret value to store securely
        """
        # Precondition: value must be str or bytes
        assert isinstance(value, (str, bytes)), (
            f"SecureString requires str or bytes, got {type(value).__name__}. "
            f"Ensure the secret value is a string or bytes object."
        )

        # Convert to bytes if string
        if isinstance(value, str):
            data = value.encode('utf-8')
        else:
            data = value

        self._length = len(data)
        self._eradicated = False

        # Allocate ctypes buffer (we control this memory)
        self._buffer = (ctypes.c_char * self._length)()

        # Copy data into our controlled buffer
        ctypes.memmove(self._buffer, data, self._length)

        # Postcondition: buffer contents must match the source data
        assert bytes(self._buffer) == data, (
            "SecureString buffer contents do not match source data after copy. "
            "ctypes.memmove may have failed or buffer was incorrectly allocated."
        )

    def _check_eradicated(self) -> None:
        """Raise if the string has been eradicated."""
        if self._eradicated:
            raise SecureStringEradicated(
                "SecureString has been eradicated and cannot be accessed"
            )

    def __str__(self) -> str:
        """
        Return a safe representation - NEVER the actual secret.

        To get the actual value, use reveal() explicitly.
        This prevents accidental leakage via str() in logging, f-strings, etc.
        """
        if self._eradicated:
            return "<eradicated>"
        return "<hidden>"

    def __bytes__(self) -> bytes:
        """
        Return a safe representation - NEVER the actual secret.

        To get the actual value, use reveal_bytes() explicitly.
        """
        if self._eradicated:
            return b"<eradicated>"
        return b"<hidden>"

    def reveal(self) -> str:
        """
        Explicitly reveal the secret as a string.

        This method name makes the intent clear: you are deliberately
        accessing a secret value. Use this when passing to APIs that
        require the actual string value (e.g., asyncssh password parameter).

        Returns:
            The actual secret string

        Raises:
            SecureStringEradicated: If the string has been eradicated
        """
        self._check_eradicated()
        result = bytes(self._buffer).decode('utf-8')
        # Postcondition: revealed data length must match stored length
        assert len(result.encode('utf-8')) == self._length, (
            f"Revealed string encodes to {len(result.encode('utf-8'))} bytes "
            f"but expected {self._length}. Buffer may be corrupted."
        )
        return result

    def reveal_bytes(self) -> bytes:
        """
        Explicitly reveal the secret as bytes.

        This method name makes the intent clear: you are deliberately
        accessing a secret value.

        Returns:
            The actual secret as bytes

        Raises:
            SecureStringEradicated: If the string has been eradicated
        """
        self._check_eradicated()
        result = bytes(self._buffer)
        # Postcondition: revealed bytes length must match stored length
        assert len(result) == self._length, (
            f"Revealed bytes length {len(result)} does not match "
            f"expected length {self._length}. Buffer may be corrupted."
        )
        return result

    def __repr__(self) -> str:
        """Return a safe representation that never reveals the secret."""
        if self._eradicated:
            return "SecureString(<eradicated>)"
        return "SecureString(<hidden>)"

    def __len__(self) -> int:
        """Return the length in bytes."""
        self._check_eradicated()
        return self._length

    def __hash__(self) -> int:
        """Return a hash of the value."""
        self._check_eradicated()
        return hash(bytes(self._buffer))

    def __eq__(self, other: Any) -> bool:
        """Compare equality with string, bytes, or SecureString."""
        self._check_eradicated()
        if isinstance(other, SecureString):
            other._check_eradicated()
            return bytes(self._buffer) == bytes(other._buffer)
        if isinstance(other, str):
            return self.reveal() == other
        if isinstance(other, bytes):
            return bytes(self._buffer) == other
        return NotImplemented

    def __bool__(self) -> bool:
        """Return True if non-empty."""
        self._check_eradicated()
        return self._length > 0

    def eradicate(self) -> None:
        """
        Overwrite memory with cryptographically secure random bytes.

        After calling this method:
        - The secret data is destroyed
        - Any attempt to access the string raises SecureStringEradicated
        - __hash__ and __eq__ raise errors

        This method is idempotent - calling it multiple times is safe.
        """
        if not self._eradicated:
            # Overwrite with cryptographically secure random bytes
            # os.urandom uses CryptGenRandom on Windows, /dev/urandom on Unix
            random_bytes = os.urandom(self._length)
            ctypes.memmove(self._buffer, random_bytes, self._length)

            # Postcondition: buffer must contain the random bytes, not original data
            assert bytes(self._buffer) == random_bytes, (
                "Eradication failed: buffer contents do not match overwrite bytes. "
                "Secret data may not have been destroyed."
            )

            self._eradicated = True

    @property
    def is_eradicated(self) -> bool:
        """Check if the string has been eradicated."""
        return self._eradicated

    def __del__(self):
        """Eradicate on garbage collection as a safety net."""
        try:
            self.eradicate()
        except Exception as e:
            warnings.warn(
                f"SecureString.__del__ failed to eradicate: {e}",
                RuntimeWarning,
                stacklevel=1,
            )
