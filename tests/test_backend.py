import pytest

from tlog_scales.backend import HttpBackend, LocalBackend, make_backend


class TestMakeBackend:
    def test_absolute_path(self) -> None:
        assert isinstance(make_backend("/some/path"), LocalBackend)

    def test_relative_path(self) -> None:
        assert isinstance(make_backend("./some/path"), LocalBackend)

    def test_file_url(self) -> None:
        assert isinstance(make_backend("file:///some/path"), LocalBackend)

    def test_https_url(self) -> None:
        assert isinstance(make_backend("https://example.com/log"), HttpBackend)

    def test_http_url(self) -> None:
        assert isinstance(make_backend("http://example.com/log"), HttpBackend)

    def test_unknown_scheme_raises(self) -> None:
        with pytest.raises(ValueError):
            make_backend("ftp://example.com/log")
