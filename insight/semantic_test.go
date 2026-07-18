package insight

import "testing"

func TestSemanticGroupsReadTools(t *testing.T) {
	g := NewSemanticGrouper(0)
	tools := map[string]string{
		"read_file":     "read a file from disk",
		"read_document": "read a document",
		"write_file":    "write a file to disk",
		"delete_all":    "delete everything",
	}
	groups := g.Group(tools)

	// read_file and read_document should land in the same group.
	same := false
	for _, grp := range groups {
		if contains(grp, "read_file") && contains(grp, "read_document") {
			same = true
		}
		if contains(grp, "read_file") && contains(grp, "delete_all") {
			t.Errorf("read and delete tools should not group together: %v", grp)
		}
	}
	if !same {
		t.Errorf("expected read_file and read_document to group; got %v", groups)
	}
}

func TestNoveltyScoresNewTool(t *testing.T) {
	g := NewSemanticGrouper(0)
	known := []string{"read_file", "read_document", "list_dir"}

	// A synonym of a known tool is LESS novel than an unrelated one.
	synonym := g.Novelty("read_report", known)
	unrelated := g.Novelty("transfer_funds", known)
	if synonym >= unrelated {
		t.Errorf("a read-synonym (%.3f) should be less novel than transfer_funds (%.3f)", synonym, unrelated)
	}
	// An empty history is maximally novel.
	if g.Novelty("anything", nil) != 1 {
		t.Error("novelty against no history should be 1")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
