# TOOLS/tests/test_browser_auth.py
from auth.browser_auth import parse_surface_urls


class TestParseSurfaceUrls:
    def _item(self, url):
        return {"url": url, "title": "test"}

    def test_keeps_same_domain(self):
        result = parse_surface_urls([self._item("https://example.com/page")], "example.com")
        assert len(result) == 1

    def test_keeps_subdomain(self):
        result = parse_surface_urls([self._item("https://api.example.com/v1")], "example.com")
        assert len(result) == 1

    def test_excludes_different_domain(self):
        result = parse_surface_urls([self._item("https://evil.com/page")], "example.com")
        assert result == []

    def test_excludes_css(self):
        result = parse_surface_urls([self._item("https://example.com/style.css")], "example.com")
        assert result == []

    def test_excludes_image_png(self):
        result = parse_surface_urls([self._item("https://example.com/img.png")], "example.com")
        assert result == []

    def test_excludes_image_jpg(self):
        result = parse_surface_urls([self._item("https://example.com/photo.jpg")], "example.com")
        assert result == []

    def test_keeps_js(self):
        result = parse_surface_urls([self._item("https://example.com/app.js")], "example.com")
        assert len(result) == 1

    def test_excludes_non_http(self):
        result = parse_surface_urls([self._item("ftp://example.com/file")], "example.com")
        assert result == []

    def test_empty_url(self):
        result = parse_surface_urls([{"url": "", "title": ""}], "example.com")
        assert result == []

    def test_www_subdomain_treated_as_same(self):
        result = parse_surface_urls([self._item("https://www.example.com/page")], "example.com")
        assert len(result) == 1

    def test_multiple_mixed(self):
        items = [
            self._item("https://example.com/api"),
            self._item("https://example.com/icon.svg"),
            self._item("https://other.com/page"),
            self._item("https://sub.example.com/data"),
        ]
        result = parse_surface_urls(items, "example.com")
        assert len(result) == 2  # /api and sub.example.com/data
