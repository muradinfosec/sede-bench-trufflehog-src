package salesforcerefreshtoken

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestSalesforcerefreshtoken_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "simple case: one of each component",
			input: `



			`,
			want: []string{

			},
		},
		{
			name: "combinatorial test: multiple keys, one refresh token and secret",
			input: `




			`,
			want: []string{


			},
		},
		{
			name: "combinatorial test: two refresh tokens, two keys, one secret",
			input: `





			`,
			want: []string{




			},
		},
		{
			name:  "negative case: invalid refresh token component",
			input: `salesforce_refresh_token = "5Aep86111", salesforce_key = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7"`,
			want:  []string{},
		},
		{
			name:  "negative case: missing refresh token component",
			input: `salesforce_key = "3MVG9dBDux2v1sLoreCoilvmnP337XNeiV01JFJ8uAAVVyH5qX0NPaa0d54El.Wkce6JTB1LmsxhzVaaa.VZ7"`,
			want:  []string{},
		},
		{
			name:  "negative case: missing secret component",

			want:  []string{},
		},
		{
			name:  "negative case: invalid key format",

			want:  []string{},
		},
		{
			name:  "negative case: invalid secret format (too short)",

			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}

			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
