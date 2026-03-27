package osv

import (
	"testing"
)

func TestParseEcosystemsTxt_Variants(t *testing.T) {
	cases := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "MultipleLines_ReturnsParsedSlice",
			data: "npm\nPyPI\nGo\n",
			want: []string{"npm", "PyPI", "Go"},
		},
		{
			name: "EmptyLines_Skipped",
			data: "npm\n\nPyPI\n\n",
			want: []string{"npm", "PyPI"},
		},
		{
			name: "WhitespaceLines_Skipped",
			data: "npm\n  \nPyPI\n",
			want: []string{"npm", "PyPI"},
		},
		{
			name: "NoTrailingNewline_StillParsed",
			data: "npm\nPyPI",
			want: []string{"npm", "PyPI"},
		},
		{
			name: "EmptyInput_ReturnsNil",
			data: "",
			want: nil,
		},
		{
			name: "EcosystemWithSpaces_Preserved",
			data: "GitHub Actions\nRed Hat\n",
			want: []string{"GitHub Actions", "Red Hat"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseEcosystemsTxt([]byte(tt.data))
			if len(got) != len(tt.want) {
				t.Fatalf("ParseEcosystemsTxt() got %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ParseEcosystemsTxt()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
