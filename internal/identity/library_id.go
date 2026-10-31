package identity

import (
	"fmt"
	"strings"
)

const MaxLibraryId = 9_999_999

// LibraryIdSequence is updated in the same transaction as the new user.
type LibraryIdSequence struct {
	ID    uint `gorm:"primaryKey;autoIncrement:false"`
	Value int  `gorm:"not null"`
}

func FormatLibraryId(id int) (string, error) {
	if id < 1 || id > MaxLibraryId {
		return "", fmt.Errorf("LibraryId must be between 1 and %d", MaxLibraryId)
	}
	return fmt.Sprintf("%07d", id), nil
}

// LibraryBarcode adds the GS1 modulo-10 check digit to the seven-digit ID.
func LibraryBarcode(id int) (string, error) {
	digits, err := FormatLibraryId(id)
	if err != nil {
		return "", err
	}
	sum := 0
	for i, digit := range digits {
		weight := 1
		if i%2 == 0 {
			weight = 3
		}
		sum += int(digit-'0') * weight
	}
	return fmt.Sprintf("%s%d", digits, (10-sum%10)%10), nil
}

// LibraryBarcodeSVG renders an EAN-8 symbol with seven-module quiet zones.
func LibraryBarcodeSVG(id int) (string, error) {
	digits, err := LibraryBarcode(id)
	if err != nil {
		return "", err
	}
	left := [10]string{"0001101", "0011001", "0010011", "0111101", "0100011", "0110001", "0101111", "0111011", "0110111", "0001011"}
	bits := "101"
	for i := 0; i < 4; i++ {
		bits += left[digits[i]-'0']
	}
	bits += "01010"
	for i := 4; i < 8; i++ {
		for _, bit := range left[digits[i]-'0'] {
			if bit == '0' {
				bits += "1"
			} else {
				bits += "0"
			}
		}
	}
	bits += "101"
	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 81 66" width="324" height="264" role="img" aria-label="%s"><rect width="81" height="66" fill="white"/><g fill="black" shape-rendering="crispEdges">`, digits)
	for i, bit := range bits {
		if bit == '1' {
			height := 50
			if i < 3 || (i >= 31 && i < 36) || i >= 64 {
				height = 55
			}
			fmt.Fprintf(&svg, `<rect x="%d" y="2" width="1" height="%d"/>`, i+7, height)
		}
	}
	fmt.Fprintf(&svg, `</g><text x="40.5" y="64" text-anchor="middle" font-family="monospace" font-size="7">%s</text></svg>`, digits)
	return svg.String(), nil
}
