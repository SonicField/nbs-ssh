"""
Tests for input validation functions.

Tests validate_hostname, validate_username, and validate_port
to ensure they correctly accept valid inputs and reject invalid ones.
"""

import pytest

from nbs_ssh.validation import (
    validate_hostname,
    validate_port,
    validate_username,
    MAX_HOSTNAME_LENGTH,
    MAX_LABEL_LENGTH,
    MAX_USERNAME_LENGTH,
    DANGEROUS_CHARS,
)


class TestValidateHostname:
    """Tests for validate_hostname function."""

    def test_valid_simple_hostname(self) -> None:
        """Accept simple valid hostnames."""
        assert validate_hostname("localhost") == "localhost"
        assert validate_hostname("example") == "example"
        assert validate_hostname("server1") == "server1"

    def test_valid_fqdn(self) -> None:
        """Accept fully qualified domain names."""
        assert validate_hostname("example.com") == "example.com"
        assert validate_hostname("sub.example.com") == "sub.example.com"
        assert validate_hostname("a.b.c.example.com") == "a.b.c.example.com"

    def test_valid_with_hyphens(self) -> None:
        """Accept hostnames with hyphens in the middle."""
        assert validate_hostname("my-server") == "my-server"
        assert validate_hostname("my-server.example.com") == "my-server.example.com"
        assert validate_hostname("a-b-c") == "a-b-c"

    def test_valid_numeric(self) -> None:
        """Accept hostnames with numbers."""
        assert validate_hostname("server1") == "server1"
        assert validate_hostname("1server") == "1server"
        assert validate_hostname("123") == "123"
        assert validate_hostname("192-168-1-1") == "192-168-1-1"

    def test_normalises_to_lowercase(self) -> None:
        """Normalise hostnames to lowercase."""
        assert validate_hostname("EXAMPLE.COM") == "example.com"
        assert validate_hostname("Example.Com") == "example.com"
        assert validate_hostname("LOCALHOST") == "localhost"

    def test_valid_single_char_labels(self) -> None:
        """Accept single character labels."""
        assert validate_hostname("a") == "a"
        assert validate_hostname("a.b.c") == "a.b.c"
        assert validate_hostname("1") == "1"

    def test_max_length_hostname(self) -> None:
        """Accept hostname at exactly max length."""
        # Create a hostname of exactly 253 characters
        # Use labels of 63 chars each: 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        label63 = "a" * 63
        label61 = "a" * 61
        hostname = f"{label63}.{label63}.{label63}.{label61}"
        assert len(hostname) == MAX_HOSTNAME_LENGTH
        assert validate_hostname(hostname) == hostname

    def test_max_length_label(self) -> None:
        """Accept label at exactly max length."""
        label = "a" * MAX_LABEL_LENGTH
        assert validate_hostname(label) == label

    def test_empty_hostname_rejected(self) -> None:
        """Reject empty hostnames."""
        with pytest.raises(ValueError, match="must not be empty"):
            validate_hostname("")

    def test_none_hostname_rejected(self) -> None:
        """Reject None hostname with type error, not empty error."""
        with pytest.raises(ValueError, match="must be a string"):
            validate_hostname(None)  # type: ignore

    def test_too_long_hostname_rejected(self) -> None:
        """Reject hostnames exceeding max length."""
        hostname = "a" * (MAX_HOSTNAME_LENGTH + 1)
        with pytest.raises(ValueError, match="exceeds maximum length"):
            validate_hostname(hostname)

    def test_too_long_label_rejected(self) -> None:
        """Reject labels exceeding max length."""
        label = "a" * (MAX_LABEL_LENGTH + 1)
        with pytest.raises(ValueError, match="label.*exceeds maximum length"):
            validate_hostname(label)

    def test_leading_dot_rejected(self) -> None:
        """Reject hostnames starting with a dot."""
        with pytest.raises(ValueError, match="must not start with a dot"):
            validate_hostname(".example.com")

    def test_trailing_dot_rejected(self) -> None:
        """Reject hostnames ending with a dot."""
        with pytest.raises(ValueError, match="must not end with a dot"):
            validate_hostname("example.com.")

    def test_consecutive_dots_rejected(self) -> None:
        """Reject hostnames with consecutive dots."""
        with pytest.raises(ValueError, match="consecutive dots"):
            validate_hostname("example..com")

    def test_leading_hyphen_label_rejected(self) -> None:
        """Reject labels starting with a hyphen."""
        with pytest.raises(ValueError, match="must not start with a hyphen"):
            validate_hostname("-example.com")
        with pytest.raises(ValueError, match="must not start with a hyphen"):
            validate_hostname("sub.-example.com")

    def test_trailing_hyphen_label_rejected(self) -> None:
        """Reject labels ending with a hyphen."""
        with pytest.raises(ValueError, match="must not end with a hyphen"):
            validate_hostname("example-.com")
        with pytest.raises(ValueError, match="must not end with a hyphen"):
            validate_hostname("sub.example-.com")

    def test_underscore_rejected(self) -> None:
        """Reject hostnames with underscores (not RFC compliant)."""
        with pytest.raises(ValueError, match="invalid characters"):
            validate_hostname("my_server")

    def test_space_rejected(self) -> None:
        """Reject hostnames with spaces."""
        with pytest.raises(ValueError, match="invalid characters"):
            validate_hostname("my server")

    def test_null_byte_rejected(self) -> None:
        """Reject hostnames with null bytes."""
        with pytest.raises(ValueError, match="null byte"):
            validate_hostname("example\x00.com")

    def test_newline_rejected(self) -> None:
        """Reject hostnames with newlines."""
        with pytest.raises(ValueError, match="newline"):
            validate_hostname("example\n.com")

    def test_carriage_return_rejected(self) -> None:
        """Reject hostnames with carriage returns."""
        with pytest.raises(ValueError, match="carriage return"):
            validate_hostname("example\r.com")

    def test_shell_metacharacters_rejected(self) -> None:
        """Reject hostnames with shell metacharacters."""
        dangerous = ["`", "$", "(", ")", "{", "}", "[", "]", "|", ";", "&", "<", ">", "\\", "'", '"']
        for char in dangerous:
            with pytest.raises(ValueError, match="forbidden character"):
                validate_hostname(f"example{char}com")

    def test_backtick_injection_rejected(self) -> None:
        """Reject backtick command injection attempts."""
        with pytest.raises(ValueError, match="forbidden character"):
            validate_hostname("`whoami`")
        with pytest.raises(ValueError, match="forbidden character"):
            validate_hostname("example.`id`.com")

    def test_dollar_injection_rejected(self) -> None:
        """Reject dollar sign command injection attempts."""
        with pytest.raises(ValueError, match="forbidden character"):
            validate_hostname("$(whoami)")
        with pytest.raises(ValueError, match="forbidden character"):
            validate_hostname("example.$(id).com")

    def test_unicode_rejected(self) -> None:
        """Reject hostnames with unicode characters."""
        with pytest.raises(ValueError, match="invalid characters"):
            validate_hostname("exämple.com")
        with pytest.raises(ValueError, match="invalid characters"):
            validate_hostname("пример.com")


class TestValidateUsername:
    """Tests for validate_username function."""

    def test_valid_simple_username(self) -> None:
        """Accept simple valid usernames."""
        assert validate_username("root") == "root"
        assert validate_username("admin") == "admin"
        assert validate_username("user") == "user"

    def test_valid_with_numbers(self) -> None:
        """Accept usernames with numbers (not at start)."""
        assert validate_username("user1") == "user1"
        assert validate_username("admin123") == "admin123"

    def test_valid_with_underscore(self) -> None:
        """Accept usernames with underscores."""
        assert validate_username("_user") == "_user"
        assert validate_username("user_name") == "user_name"
        assert validate_username("_") == "_"

    def test_valid_with_hyphen(self) -> None:
        """Accept usernames with hyphens (not at start)."""
        assert validate_username("user-name") == "user-name"
        assert validate_username("my-user") == "my-user"

    def test_valid_max_length(self) -> None:
        """Accept username at exactly max length."""
        username = "a" * MAX_USERNAME_LENGTH
        assert validate_username(username) == username

    def test_empty_username_rejected(self) -> None:
        """Reject empty usernames."""
        with pytest.raises(ValueError, match="must not be empty"):
            validate_username("")

    def test_none_username_rejected(self) -> None:
        """Reject None username with type error, not empty error."""
        with pytest.raises(ValueError, match="must be a string"):
            validate_username(None)  # type: ignore

    def test_too_long_username_rejected(self) -> None:
        """Reject usernames exceeding max length."""
        username = "a" * (MAX_USERNAME_LENGTH + 1)
        with pytest.raises(ValueError, match="exceeds maximum length"):
            validate_username(username)

    def test_starting_with_number_rejected(self) -> None:
        """Reject usernames starting with a number."""
        with pytest.raises(ValueError, match="must start with a letter or underscore"):
            validate_username("1user")
        with pytest.raises(ValueError, match="must start with a letter or underscore"):
            validate_username("123")

    def test_starting_with_hyphen_rejected(self) -> None:
        """Reject usernames starting with a hyphen."""
        with pytest.raises(ValueError, match="must start with a letter or underscore"):
            validate_username("-user")

    def test_space_rejected(self) -> None:
        """Reject usernames with spaces."""
        with pytest.raises(ValueError, match="invalid character"):
            validate_username("user name")

    def test_dot_rejected(self) -> None:
        """Reject usernames with dots."""
        with pytest.raises(ValueError, match="invalid character"):
            validate_username("user.name")

    def test_null_byte_rejected(self) -> None:
        """Reject usernames with null bytes."""
        with pytest.raises(ValueError, match="null byte"):
            validate_username("user\x00name")

    def test_newline_rejected(self) -> None:
        """Reject usernames with newlines."""
        with pytest.raises(ValueError, match="newline"):
            validate_username("user\nname")

    def test_shell_metacharacters_rejected(self) -> None:
        """Reject usernames with shell metacharacters."""
        dangerous = ["`", "$", "(", ")", "{", "}", "[", "]", "|", ";", "&", "<", ">", "\\", "'", '"']
        for char in dangerous:
            with pytest.raises(ValueError, match="forbidden character"):
                validate_username(f"user{char}name")

    def test_injection_attempts_rejected(self) -> None:
        """Reject common injection patterns."""
        with pytest.raises(ValueError, match="forbidden character"):
            validate_username("user$(id)")
        with pytest.raises(ValueError, match="forbidden character"):
            validate_username("user`whoami`")
        with pytest.raises(ValueError, match="forbidden character"):
            validate_username("user;rm -rf /")

    def test_unicode_rejected(self) -> None:
        """Reject usernames with unicode characters."""
        with pytest.raises(ValueError, match="invalid character"):
            validate_username("usér")
        with pytest.raises(ValueError, match="invalid character"):
            validate_username("用户")


class TestValidatePort:
    """Tests for validate_port function."""

    def test_valid_standard_ports(self) -> None:
        """Accept standard SSH ports."""
        assert validate_port(22) == 22
        assert validate_port(2222) == 2222

    def test_valid_min_port(self) -> None:
        """Accept minimum valid port."""
        assert validate_port(1) == 1

    def test_valid_max_port(self) -> None:
        """Accept maximum valid port."""
        assert validate_port(65535) == 65535

    def test_valid_common_ports(self) -> None:
        """Accept various common ports."""
        assert validate_port(80) == 80
        assert validate_port(443) == 443
        assert validate_port(8080) == 8080

    def test_zero_port_rejected(self) -> None:
        """Reject port 0."""
        with pytest.raises(ValueError, match="must be at least 1"):
            validate_port(0)

    def test_negative_port_rejected(self) -> None:
        """Reject negative ports."""
        with pytest.raises(ValueError, match="must be at least 1"):
            validate_port(-1)
        with pytest.raises(ValueError, match="must be at least 1"):
            validate_port(-22)

    def test_too_high_port_rejected(self) -> None:
        """Reject ports above 65535."""
        with pytest.raises(ValueError, match="must be at most 65535"):
            validate_port(65536)
        with pytest.raises(ValueError, match="must be at most 65535"):
            validate_port(100000)

    def test_string_port_rejected(self) -> None:
        """Reject string ports."""
        with pytest.raises(ValueError, match="must be an integer"):
            validate_port("22")  # type: ignore

    def test_float_port_rejected(self) -> None:
        """Reject float ports."""
        with pytest.raises(ValueError, match="must be an integer"):
            validate_port(22.0)  # type: ignore

    def test_none_port_rejected(self) -> None:
        """Reject None port."""
        with pytest.raises(ValueError, match="must be an integer"):
            validate_port(None)  # type: ignore

    def test_bool_port_rejected(self) -> None:
        """Reject boolean ports (even though bool is subclass of int)."""
        with pytest.raises(ValueError, match="must be an integer, got bool"):
            validate_port(True)  # type: ignore
        with pytest.raises(ValueError, match="must be an integer, got bool"):
            validate_port(False)  # type: ignore


class TestDangerousCharacters:
    """Tests for dangerous character detection."""

    def test_all_dangerous_chars_in_hostname(self) -> None:
        """Verify all dangerous characters are rejected in hostnames."""
        for char in DANGEROUS_CHARS:
            with pytest.raises(ValueError, match="forbidden character"):
                validate_hostname(f"example{char}com")

    def test_all_dangerous_chars_in_username(self) -> None:
        """Verify all dangerous characters are rejected in usernames."""
        for char in DANGEROUS_CHARS:
            with pytest.raises(ValueError, match="forbidden character"):
                validate_username(f"user{char}name")

    def test_dangerous_chars_at_start(self) -> None:
        """Detect dangerous characters at the start of values."""
        with pytest.raises(ValueError, match="forbidden character"):
            validate_hostname(";example.com")

    def test_dangerous_chars_at_end(self) -> None:
        """Detect dangerous characters at the end of values."""
        with pytest.raises(ValueError, match="forbidden character"):
            validate_hostname("example.com;")

    def test_multiple_dangerous_chars(self) -> None:
        """Detect the first dangerous character when multiple present."""
        with pytest.raises(ValueError, match="forbidden character"):
            validate_hostname("$example;.com")
