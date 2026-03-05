package flamegraph

import "testing"

func TestFixtureSnapshotsHaveApproximateFrameCounts(t *testing.T) {
	fixtures := []struct {
		name    string
		depth   int
		breadth int
		expect  int
	}{
		{name: "small", depth: fixtureSmallDepth, breadth: fixtureSmallBreadth, expect: 121},
		{name: "medium", depth: fixtureMediumDepth, breadth: fixtureMediumBreadth, expect: 2500},
		{name: "large", depth: fixtureLargeDepth, breadth: fixtureLargeBreadth, expect: 12000},
		{name: "deep", depth: fixtureDeepDepth, breadth: fixtureDeepBreadth, expect: 100},
		{name: "wide", depth: fixtureWideDepth, breadth: fixtureWideBreadth, expect: 5000},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			snap := generateTestSnapshot(fixture.depth, fixture.breadth)
			got := snapshotNodeCount(snap)
			if !approxEqualCount(got, fixture.expect) {
				t.Fatalf("%s fixture nodes=%d, expected approximately %d", fixture.name, got, fixture.expect)
			}
		})
	}
}

func TestGenerateTestTrieProducesSnapshotData(t *testing.T) {
	lt := generateTestTrie(fixtureSmallDepth, fixtureSmallBreadth)
	snap, err := decodeTrieSnapshot(lt)
	if err != nil {
		t.Fatalf("decode trie snapshot: %v", err)
	}
	if snap.Total == 0 {
		t.Fatalf("expected generated trie snapshot to contain data")
	}
}
