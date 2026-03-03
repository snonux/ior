package flamegraph

import (
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"
)

type jsonNode struct {
	Name     string     `json:"name"`
	Value    uint64     `json:"value"`
	Total    uint64     `json:"total"`
	Children []jsonNode `json:"children,omitempty"`
}

type jsonFlamegraph struct {
	Fields     []string `json:"fields"`
	CountField string   `json:"countField"`
	Root       jsonNode `json:"root"`
}

func (n NativeSVG) WriteJSONFromFile(iorDataFile string) (outFile string, err error) {
	outFile = fmt.Sprintf("%s.%s-by-%s.json",
		strings.TrimSuffix(iorDataFile, ".ior.zst"),
		strings.Join(n.fields, ":"),
		n.countField,
	)
	defer func() {
		if err != nil {
			_ = os.Remove(outFile)
		}
	}()

	iod, err := newIorDataFromFile(iorDataFile)
	if err != nil {
		return outFile, fmt.Errorf("read ior data: %w", err)
	}

	fd, err := os.Create(outFile)
	if err != nil {
		return outFile, fmt.Errorf("create output %s: %w", outFile, err)
	}
	defer fd.Close()

	if err := n.WriteJSONFromIter(iod.iter(), fd); err != nil {
		return outFile, err
	}
	return outFile, nil
}

func (n NativeSVG) WriteJSONFromIter(records iter.Seq[IterRecord], w io.Writer) error {
	tr, err := n.buildTrieFromIter(records)
	if err != nil {
		return err
	}

	payload := jsonFlamegraph{
		Fields:     append([]string(nil), n.fields...),
		CountField: n.countField,
		Root:       jsonNodeFromTrieNode(tr.root, "root"),
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func jsonNodeFromTrieNode(node *trieNode, name string) jsonNode {
	out := jsonNode{
		Name:  name,
		Value: node.value,
		Total: node.total,
	}
	if len(node.children) == 0 {
		return out
	}

	out.Children = make([]jsonNode, 0, len(node.children))
	for _, child := range node.children {
		out.Children = append(out.Children, jsonNodeFromTrieNode(child, child.name))
	}
	return out
}
