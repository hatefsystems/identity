package ledgerproof

import (
	"math"
	"testing"
)

func TestSpanManifestGoldenVectors(t *testing.T) {
	for _, tc := range []struct {
		name             string
		spans            [][2]int64
		count, highwater int64
		want             string
	}{
		{"empty", nil, 0, 0, "3fa0d3928b93f6ce1441763bf3f3231347c032b5a32ae0049919228fd198acce"},
		{"singleton", [][2]int64{{1, 1}}, 1, 1, "bc88b315d7e38c91269958453c6d633588e2929eaed06c65742dab84dbb6d036"},
		{"two spans", [][2]int64{{1, 3}, {7, 9}}, 6, 20, "d2b21a56641e87017091a782271d8012fb21a0db40f689ccd81e4325c98dc737"},
		{"int64 boundary", [][2]int64{{math.MaxInt64, math.MaxInt64}}, 1, math.MaxInt64, "e70811d0f121c527bee0200af5f5d9272f43df3b52ecb3b4417b3afdf89cdf26"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SpanManifest(tc.spans, tc.count, tc.highwater)
			if err != nil || got != tc.want {
				t.Fatalf("manifest=%s error=%v, want %s", got, err, tc.want)
			}
		})
	}
}

func TestSpanManifestRejectsInvalidCoordinatesAndCounts(t *testing.T) {
	for _, tc := range []struct {
		spans            [][2]int64
		count, highwater int64
	}{
		{nil, 1, 9}, {nil, 0, -1}, {nil, -1, 0},
		{[][2]int64{{0, 1}}, 2, 9}, {[][2]int64{{-1, 1}}, 3, 9},
		{[][2]int64{{2, 1}}, 0, 9}, {[][2]int64{{1, 3}}, 3, 2},
		{[][2]int64{{1, 2}, {2, 3}}, 4, 9}, {[][2]int64{{3, 3}, {1, 1}}, 2, 9},
		{[][2]int64{{1, 2}, {3, 4}}, 4, 9}, {[][2]int64{{1, 3}}, 2, 9},
	} {
		if _, err := SpanManifest(tc.spans, tc.count, tc.highwater); err == nil {
			t.Fatalf("accepted invalid manifest %+v", tc)
		}
	}
}
