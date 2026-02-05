"""Tests for SecureString memory-safe secret storage."""
import ctypes

import pytest

from nbs_ssh.secure_string import SecureString, SecureStringEradicated


class TestSecureStringBasicOperations:
    """Test basic string operations on SecureString."""

    def test_reveal_returns_actual_value(self):
        """reveal() returns the actual secret."""
        secret = SecureString("password123")
        assert secret.reveal() == "password123"

    def test_reveal_bytes_returns_actual_value(self):
        """reveal_bytes() returns the actual secret as bytes."""
        secret = SecureString("password123")
        assert secret.reveal_bytes() == b"password123"

    def test_str_hides_value(self):
        """str() returns <hidden>, never the secret."""
        secret = SecureString("password123")
        assert str(secret) == "<hidden>"
        assert "password" not in str(secret)

    def test_bytes_hides_value(self):
        """bytes() returns b'<hidden>', never the secret."""
        secret = SecureString("password123")
        assert bytes(secret) == b"<hidden>"
        assert b"password" not in bytes(secret)

    def test_init_from_bytes(self):
        """SecureString can be initialised from bytes."""
        secret = SecureString(b"password123")
        assert secret.reveal() == "password123"
        assert secret.reveal_bytes() == b"password123"

    def test_len(self):
        """SecureString reports correct length."""
        secret = SecureString("password123")
        assert len(secret) == 11

    def test_len_bytes(self):
        """Length is in bytes, not characters."""
        # Unicode character takes multiple bytes in UTF-8
        secret = SecureString("café")  # 'é' is 2 bytes in UTF-8
        assert len(secret) == 5  # c(1) + a(1) + f(1) + é(2) = 5 bytes

    def test_bool_true(self):
        """Non-empty SecureString is truthy."""
        secret = SecureString("password")
        assert bool(secret) is True

    def test_bool_false(self):
        """Empty SecureString is falsy."""
        secret = SecureString("")
        assert bool(secret) is False


class TestSecureStringEquality:
    """Test equality comparison for SecureString."""

    def test_eq_string(self):
        """SecureString equals matching string."""
        secret = SecureString("password123")
        assert secret == "password123"
        assert not (secret == "wrongpassword")

    def test_eq_bytes(self):
        """SecureString equals matching bytes."""
        secret = SecureString("password123")
        assert secret == b"password123"
        assert not (secret == b"wrongpassword")

    def test_eq_secure_string(self):
        """SecureString equals matching SecureString."""
        secret1 = SecureString("password123")
        secret2 = SecureString("password123")
        assert secret1 == secret2

    def test_eq_different_secure_string(self):
        """SecureString not equal to different SecureString."""
        secret1 = SecureString("password123")
        secret2 = SecureString("different")
        assert not (secret1 == secret2)

    def test_eq_other_type_returns_not_implemented(self):
        """Comparing with incompatible types returns NotImplemented."""
        secret = SecureString("password123")
        assert secret.__eq__(123) is NotImplemented
        assert secret.__eq__(None) is NotImplemented
        assert secret.__eq__([]) is NotImplemented


class TestSecureStringHash:
    """Test hashing for SecureString."""

    def test_hash_consistent(self):
        """Same value produces same hash."""
        secret1 = SecureString("password123")
        secret2 = SecureString("password123")
        assert hash(secret1) == hash(secret2)

    def test_hash_different_for_different_values(self):
        """Different values produce different hashes (usually)."""
        secret1 = SecureString("password123")
        secret2 = SecureString("different")
        # While hash collisions are possible, these specific values should differ
        assert hash(secret1) != hash(secret2)

    def test_hashable_for_dict_key(self):
        """SecureString can be used as dictionary key."""
        secret = SecureString("password123")
        d = {secret: "value"}
        assert d[secret] == "value"


class TestSecureStringRepr:
    """Test repr and str never reveal secrets."""

    def test_repr_hides_secret(self):
        """repr never shows the actual secret."""
        secret = SecureString("supersecretpassword")
        r = repr(secret)
        assert "supersecret" not in r
        assert "password" not in r
        assert "<hidden>" in r
        assert "SecureString" in r

    def test_str_hides_secret(self):
        """str never shows the actual secret."""
        secret = SecureString("supersecretpassword")
        s = str(secret)
        assert "supersecret" not in s
        assert "password" not in s.lower()
        assert "<hidden>" in s

    def test_repr_shows_eradicated(self):
        """repr shows eradicated state."""
        secret = SecureString("password")
        secret.eradicate()
        r = repr(secret)
        assert "<eradicated>" in r
        assert "SecureString" in r

    def test_str_shows_eradicated(self):
        """str shows eradicated state after eradication."""
        secret = SecureString("password")
        secret.eradicate()
        assert str(secret) == "<eradicated>"


class TestSecureStringEradication:
    """Test eradicate() method."""

    def test_eradicate_sets_flag(self):
        """eradicate() sets is_eradicated flag."""
        secret = SecureString("password")
        assert secret.is_eradicated is False
        secret.eradicate()
        assert secret.is_eradicated is True

    def test_eradicate_overwrites_memory(self):
        """eradicate() overwrites memory with random bytes."""
        secret = SecureString("password")
        # Get reference to buffer before eradication
        original_bytes = bytes(secret._buffer)
        assert original_bytes == b"password"

        secret.eradicate()

        # Buffer should now contain different bytes
        new_bytes = bytes(secret._buffer)
        assert new_bytes != b"password"
        # Should be same length
        assert len(new_bytes) == 8

    def test_eradicate_idempotent(self):
        """Calling eradicate() multiple times is safe."""
        secret = SecureString("password")
        secret.eradicate()
        # Should not raise
        secret.eradicate()
        secret.eradicate()
        assert secret.is_eradicated is True

    def test_reveal_raises_after_eradicate(self):
        """reveal() raises after eradication."""
        secret = SecureString("password")
        secret.eradicate()
        with pytest.raises(SecureStringEradicated):
            secret.reveal()

    def test_reveal_bytes_raises_after_eradicate(self):
        """reveal_bytes() raises after eradication."""
        secret = SecureString("password")
        secret.eradicate()
        with pytest.raises(SecureStringEradicated):
            secret.reveal_bytes()

    def test_str_safe_after_eradicate(self):
        """str() returns <eradicated> after eradication (does not raise)."""
        secret = SecureString("password")
        secret.eradicate()
        # str() should NOT raise - it returns safe string
        assert str(secret) == "<eradicated>"

    def test_bytes_safe_after_eradicate(self):
        """bytes() returns b'<eradicated>' after eradication (does not raise)."""
        secret = SecureString("password")
        secret.eradicate()
        # bytes() should NOT raise - it returns safe bytes
        assert bytes(secret) == b"<eradicated>"

    def test_len_raises_after_eradicate(self):
        """len() raises after eradication."""
        secret = SecureString("password")
        secret.eradicate()
        with pytest.raises(SecureStringEradicated):
            len(secret)

    def test_hash_raises_after_eradicate(self):
        """hash() raises after eradication."""
        secret = SecureString("password")
        secret.eradicate()
        with pytest.raises(SecureStringEradicated):
            hash(secret)

    def test_eq_raises_after_eradicate_self(self):
        """__eq__ raises if self is eradicated."""
        secret = SecureString("password")
        secret.eradicate()
        with pytest.raises(SecureStringEradicated):
            secret == "password"

    def test_eq_raises_after_eradicate_other(self):
        """__eq__ raises if other SecureString is eradicated."""
        secret1 = SecureString("password")
        secret2 = SecureString("password")
        secret2.eradicate()
        with pytest.raises(SecureStringEradicated):
            secret1 == secret2

    def test_bool_raises_after_eradicate(self):
        """bool() raises after eradication."""
        secret = SecureString("password")
        secret.eradicate()
        with pytest.raises(SecureStringEradicated):
            bool(secret)


class TestSecureStringUnicode:
    """Test unicode handling."""

    def test_unicode_characters(self):
        """SecureString handles unicode correctly."""
        secret = SecureString("пароль")  # Russian for "password"
        assert secret.reveal() == "пароль"

    def test_unicode_emoji(self):
        """SecureString handles emoji."""
        secret = SecureString("pass🔐word")
        assert secret.reveal() == "pass🔐word"

    def test_unicode_roundtrip(self):
        """Unicode survives string->SecureString->reveal()."""
        original = "日本語パスワード"  # Japanese for "Japanese password"
        secret = SecureString(original)
        assert secret.reveal() == original


class TestSecureStringEmptyString:
    """Test edge case with empty string."""

    def test_empty_string_reveal(self):
        """Empty SecureString reveals empty string."""
        secret = SecureString("")
        assert secret.reveal() == ""

    def test_empty_string_reveal_bytes(self):
        """Empty SecureString reveals empty bytes."""
        secret = SecureString("")
        assert secret.reveal_bytes() == b""

    def test_empty_string_str_hidden(self):
        """Empty SecureString str() still shows <hidden>."""
        secret = SecureString("")
        assert str(secret) == "<hidden>"

    def test_empty_string_len(self):
        """Empty SecureString has length 0."""
        secret = SecureString("")
        assert len(secret) == 0

    def test_empty_string_eradicate(self):
        """Eradicating empty SecureString is safe."""
        secret = SecureString("")
        secret.eradicate()
        assert secret.is_eradicated is True


class TestSecureStringGarbageCollection:
    """Test __del__ behaviour."""

    def test_del_eradicates(self):
        """__del__ calls eradicate()."""
        secret = SecureString("password")
        buffer_ref = secret._buffer

        # Delete the SecureString
        del secret

        # We can't easily test the buffer contents after deletion
        # because the object is gone, but we can test that a new
        # SecureString is eradicated on del
        secret2 = SecureString("test")
        assert secret2.is_eradicated is False
        secret2.__del__()
        assert secret2.is_eradicated is True


class TestSecureStringMemoryControl:
    """Test that memory is ctypes-controlled."""

    def test_uses_ctypes_buffer(self):
        """SecureString uses ctypes buffer."""
        secret = SecureString("password")
        assert isinstance(secret._buffer, ctypes.Array)

    def test_buffer_is_c_char_array(self):
        """Buffer is a c_char array."""
        secret = SecureString("password")
        assert secret._buffer._type_ == ctypes.c_char

    def test_buffer_correct_size(self):
        """Buffer size matches string length."""
        secret = SecureString("password")
        assert len(secret._buffer) == 8


class TestSecureStringExceptionMessages:
    """Test exception messages are informative."""

    def test_eradicated_exception_message(self):
        """SecureStringEradicated has informative message."""
        secret = SecureString("password")
        secret.eradicate()
        try:
            secret.reveal()
        except SecureStringEradicated as e:
            assert "eradicated" in str(e).lower()
            assert "cannot be accessed" in str(e).lower()


class TestSecureStringExplicitReveal:
    """Test that reveal() requires explicit intent."""

    def test_accidental_str_is_safe(self):
        """Accidentally using str() in f-string is safe."""
        secret = SecureString("mysecretpassword")
        # This would happen if someone wrote f"Password: {secret}"
        message = f"Password: {secret}"
        assert "mysecret" not in message
        assert "<hidden>" in message

    def test_accidental_print_is_safe(self):
        """Accidentally printing SecureString is safe."""
        secret = SecureString("mysecretpassword")
        # str() is called implicitly by print()
        result = str(secret)
        assert "mysecret" not in result
        assert "<hidden>" in result

    def test_explicit_reveal_required(self):
        """Getting the actual value requires explicit reveal()."""
        secret = SecureString("mysecretpassword")
        # These do NOT reveal the secret:
        assert "mysecret" not in str(secret)
        assert "mysecret" not in repr(secret)
        assert b"mysecret" not in bytes(secret)
        # Only reveal() and reveal_bytes() work:
        assert secret.reveal() == "mysecretpassword"
        assert secret.reveal_bytes() == b"mysecretpassword"
