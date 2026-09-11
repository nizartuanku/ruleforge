package webui

import (
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
)

// DefaultMaxUploadBytes is the ceiling for one configuration upload request.
//
// One gibibyte is not a guess: a Cisco ASA `show running-config` of six to
// eight million lines is roughly 400-700 MB of text, and a multi-context
// capture uploaded as several files has to fit in the same request. The
// operator can move the ceiling with -max-upload; this is the default, not a
// licence limit.
const DefaultMaxUploadBytes int64 = 1 << 30 // 1_073_741_824

// maxFieldBytes caps one non-file form field (source, target, name, and the
// "config" paste box). A configuration that matters arrives as a file; the
// paste box exists for a few hundred lines someone copied out of a terminal.
const maxFieldBytes int64 = 8 << 20 // 8_388_608

// uploadedFile is one configuration file that has already been written to
// disk. The body is never held in memory as a whole — that is the difference
// between refusing a 1.2 GB upload for the cost of a 32 KB buffer and
// allocating 1.2 GB only to discover it is too big.
type uploadedFile struct {
	Name string // filename as the browser sent it, used to label the context
	Path string // temporary file; removed by removeUploads
	Size int64
}

// tooLargeError is returned when a part runs past the budget. Seen is how much
// was read before the reader gave up (always budget+1), never the true size of
// the upload — that is the whole point of stopping early.
type tooLargeError struct {
	What  string
	Limit int64
	Seen  int64
}

func (e *tooLargeError) Error() string {
	return fmt.Sprintf("%s is larger than the %d-byte upload limit", e.What, e.Limit)
}

// message is the buyer-facing 413 body. It states the limit in bytes and in
// mebibytes, says plainly that nothing was converted, and — when the client
// declared a Content-Length — how big the request actually was.
func (e *tooLargeError) message(declared int64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is larger than the %d-byte (%.0f MB) upload limit for one request.",
		e.What, e.Limit, float64(e.Limit)/(1<<20))
	if declared > 0 {
		fmt.Fprintf(&b, " This request declared %d bytes (%.1f MB).", declared, float64(declared)/(1<<20))
	}
	b.WriteString(" Nothing was converted: processing a truncated config would produce a silently incomplete report.")
	b.WriteString(" Upload the contexts as separate jobs, or start the server with a larger -max-upload if this host has the memory to parse a config that size.")
	return b.String()
}

// receiveUpload streams a multipart/form-data request to disk. Form fields
// come back as a map; every file part becomes a temporary file in dir. The
// caller owns the returned files and must call removeUploads on them.
//
// limit applies to the sum of the file parts, so ten 200 MB files are refused
// for the same reason one 2 GB file is.
func receiveUpload(r *http.Request, dir string, limit int64) (map[string]string, []uploadedFile, error) {
	if limit <= 0 {
		limit = DefaultMaxUploadBytes
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, nil, fmt.Errorf("multipart form expected: %w", err)
	}
	fields := make(map[string]string)
	var files []uploadedFile
	remaining := limit
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			removeUploads(files)
			return nil, nil, fmt.Errorf("read upload: %w", err)
		}
		name, filename := p.FormName(), p.FileName()
		if filename == "" {
			value, err := readField(p)
			p.Close()
			if err != nil {
				removeUploads(files)
				return nil, nil, err
			}
			fields[name] = value
			continue
		}
		uf, err := streamPart(p, dir, filename, remaining)
		p.Close()
		if err != nil {
			removeUploads(files)
			return nil, nil, err
		}
		if uf.Size == 0 {
			// An empty file part is not an error worth failing the request
			// over — a browser sends one for an untouched file input.
			_ = os.Remove(uf.Path)
			continue
		}
		remaining -= uf.Size
		files = append(files, uf)
	}
	return fields, files, nil
}

// readField reads one non-file part with a hard cap, so a hostile or broken
// client cannot grow the heap through a field that is supposed to hold the
// word "cisco-asa".
func readField(p *multipart.Part) (string, error) {
	b, err := io.ReadAll(io.LimitReader(p, maxFieldBytes+1))
	if err != nil {
		return "", fmt.Errorf("read field %q: %w", p.FormName(), err)
	}
	if int64(len(b)) > maxFieldBytes {
		return "", &tooLargeError{
			What:  "form field " + p.FormName(),
			Limit: maxFieldBytes,
			Seen:  int64(len(b)),
		}
	}
	return string(b), nil
}

// streamPart copies one file part to a temporary file, reading one byte past
// the budget so an oversize upload is detected rather than truncated. Memory
// stays at io.Copy's buffer whatever the size of the part.
func streamPart(p *multipart.Part, dir, filename string, budget int64) (uploadedFile, error) {
	f, err := os.CreateTemp(dir, "ruleforge-upload-*.cfg")
	if err != nil {
		return uploadedFile{}, fmt.Errorf("create temporary file: %w", err)
	}
	path := f.Name()
	n, copyErr := io.Copy(f, io.LimitReader(p, budget+1))
	closeErr := f.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(path)
		return uploadedFile{}, fmt.Errorf("write %s to disk: %w", filename, copyErr)
	case closeErr != nil:
		_ = os.Remove(path)
		return uploadedFile{}, fmt.Errorf("write %s to disk: %w", filename, closeErr)
	case n > budget:
		_ = os.Remove(path)
		return uploadedFile{}, &tooLargeError{What: filename, Limit: budget, Seen: n}
	}
	return uploadedFile{Name: filename, Path: path, Size: n}, nil
}

// removeUploads deletes the temporary files. Errors are ignored on purpose:
// the request is already answered, and a leftover file in the temp directory
// is not worth a 500.
func removeUploads(files []uploadedFile) {
	for _, f := range files {
		_ = os.Remove(f.Path)
	}
}

// readUpload returns the contents of a streamed upload as a string without
// paying for it twice. strings.Builder hands its buffer to the string without
// copying, and Grow sizes that buffer once, so peak memory is one copy of the
// file rather than the two that os.ReadFile followed by string(b) costs.
func readUpload(f uploadedFile) (string, error) {
	h, err := os.Open(f.Path)
	if err != nil {
		return "", err
	}
	defer h.Close()
	var sb strings.Builder
	if f.Size > 0 && f.Size <= math.MaxInt {
		sb.Grow(int(f.Size)) // one allocation; Grow is skipped rather than overflowing int on a 32-bit build
	}
	if _, err := io.Copy(&sb, h); err != nil {
		return "", err
	}
	return sb.String(), nil
}
