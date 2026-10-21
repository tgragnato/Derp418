package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultDataDir(t *testing.T) {
	t.Parallel()

	dir := defaultDataDir()
	if dir == "" {
		t.Skip("no user config directory in this environment")
	}

	if filepath.Base(dir) != "derp418" {
		t.Errorf("defaultDataDir() = %q, want a derp418 directory", dir)
	}

	if !filepath.IsAbs(dir) {
		t.Errorf("defaultDataDir() = %q is not absolute", dir)
	}
}

func TestLoadNodeKeyCreatedOnceThenReused(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "dir", "derper.key")

	first, err := loadNodeKey(path)
	if err != nil {
		t.Fatal(err)
	}

	if first.IsZero() {
		t.Fatal("zero key")
	}

	second, err := loadNodeKey(path)
	if err != nil {
		t.Fatal(err)
	}

	if !first.Equal(second) {
		t.Error("the key changed between loads")
	}
}

func TestLoadNodeKeyDistinctFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	first, err := loadNodeKey(filepath.Join(dir, "a.key"))
	if err != nil {
		t.Fatal(err)
	}

	second, err := loadNodeKey(filepath.Join(dir, "b.key"))
	if err != nil {
		t.Fatal(err)
	}

	if first.Equal(second) {
		t.Error("two nodes got the same key")
	}
}

func TestLoadNodeKeyPrivatePermissions(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}

	path := filepath.Join(t.TempDir(), "derper.key")

	_, err := loadNodeKey(path)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %v, want 0600", perm)
	}
}

func TestLoadNodeKeyCorruptFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "derper.key")

	err := os.WriteFile(path, []byte("not a key"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = loadNodeKey(path)
	if err == nil {
		t.Fatal("accepted a corrupt key file")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != "not a key" {
		t.Errorf("the corrupt file was overwritten: %q", content)
	}
}

func TestLoadNodeKeyUnwritableLocation(t *testing.T) {
	t.Parallel()

	// A regular file where a directory is needed.
	file := filepath.Join(t.TempDir(), "file")

	err := os.WriteFile(file, nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, err = loadNodeKey(filepath.Join(file, "derper.key"))
	if err == nil {
		t.Fatal("no error")
	}
}

func TestRedirectToHTTPS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, host, uri, want string
	}{
		{"root", testHost, "/", "https://a.example.org/"},
		{"path and query", testHost, "/x/y?z=1&w=%20", "https://a.example.org/x/y?z=1&w=%20"},
		{"encoded slash", testHost, "/x%2Fy", "https://a.example.org/x%2Fy"},
		{"host with port", testHost + ":80", "/", "https://a.example.org:80/"},
	}
	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tcase.uri, nil)
			request.Host = tcase.host
			recorder := httptest.NewRecorder()
			redirectToHTTPS(recorder, request)

			if recorder.Code != http.StatusMovedPermanently {
				t.Errorf("status = %d, want 301", recorder.Code)
			}

			if got := recorder.Header().Get("Location"); got != tcase.want {
				t.Errorf("Location = %q, want %q", got, tcase.want)
			}
		})
	}

	t.Run("any method", func(t *testing.T) {
		t.Parallel()

		methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut}
		for _, method := range methods {
			request := httptest.NewRequestWithContext(t.Context(), method, "/", nil)
			recorder := httptest.NewRecorder()
			redirectToHTTPS(recorder, request)

			if recorder.Code != http.StatusMovedPermanently {
				t.Errorf("%s: status = %d", method, recorder.Code)
			}
		}
	})
}
