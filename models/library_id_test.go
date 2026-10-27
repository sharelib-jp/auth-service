package models

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestLibraryBarcode(t *testing.T) {
	for _, test := range []struct {
		id                 int
		formatted, barcode string
	}{
		{1, "0000001", "00000017"},
		{1234567, "1234567", "12345670"},
		{5512345, "5512345", "55123457"},
		{9999999, "9999999", "99999995"},
	} {
		formatted, err := FormatLibraryId(test.id)
		if err != nil || formatted != test.formatted {
			t.Fatalf("FormatLibraryId(%d) = %q, %v", test.id, formatted, err)
		}
		barcode, err := LibraryBarcode(test.id)
		if err != nil || barcode != test.barcode {
			t.Fatalf("LibraryBarcode(%d) = %q, %v; want %q", test.id, barcode, err, test.barcode)
		}
	}
	for _, id := range []int{-1, 0, 10_000_000} {
		if _, err := LibraryBarcode(id); err == nil {
			t.Fatalf("invalid LibraryId %d accepted", id)
		}
		if _, err := LibraryBarcodeSVG(id); err == nil {
			t.Fatalf("invalid SVG LibraryId %d accepted", id)
		}
	}
}

func TestLibraryBarcodeSVG(t *testing.T) {
	svg, err := LibraryBarcodeSVG(1)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(strings.NewReader(svg))
	var bars strings.Builder
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if element, ok := token.(xml.StartElement); ok && element.Name.Local == "rect" {
			for _, attr := range element.Attr {
				if attr.Name.Local == "x" {
					bars.WriteString(attr.Value + ",")
				}
			}
		}
	}
	if bars.Len() == 0 || !strings.Contains(svg, `aria-label="00000017"`) || !strings.Contains(svg, `viewBox="0 0 81 66"`) {
		t.Fatalf("invalid barcode SVG: %s", svg)
	}
}
