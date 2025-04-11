package flamegraph

import (
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/zstd"
)

// Collapsed represents a structure used to process and store information
// related to a collapsed flamegraph. It includes the following fields:
//   - iorFile: The path to the input/output report file.
//   - fields: A list of field names used in the flamegraph processing.
//   - countField: The name of the field that represents the count or weight
//     in the flamegraph data.
type Collapsed struct {
	iorFile    string   // Path to the input/output report file.
	fields     []string // List of field names used in processing.
	countField string   // Field name representing the count or weight.
}

func NewCollapsed(iorFile string, fields []string, countField string) Collapsed {
	return Collapsed{iorFile: iorFile, fields: fields, countField: countField}
}

func (c Collapsed) Write(iorDataFile string) (string, error) {
	outFile := fmt.Sprintf("%s.%s-by-%s.collapsed.zst",
		strings.TrimSuffix(iorDataFile, ".ior.zst"),
		strings.Join(c.fields, ":"),
		c.countField,
	)

	if _, err := os.Stat(outFile); err == nil {
		fmt.Println(outFile, "already exists!")
		return outFile, nil
	}

	// outFD should be zstd compressed
	outFd, err := os.Create(outFile)
	if err != nil {
		return outFile, err
	}
	defer outFd.Close()

	fmt.Println("Reading", iorDataFile)
	iod, err := newIorDataFromFile(iorDataFile)
	if err != nil {
		return outFile, err
	}

	fmt.Println("Writing", outFile)
	writer := zstd.NewWriter(outFd)
	if err != nil {
		return outFile, err
	}
	defer writer.Close()

	for record := range iod.iter() {
		var fieldValues []string
		for _, fieldName := range c.fields {
			fieldValues = append(fieldValues, record.StringByName(fieldName))
		}
		writer.Write([]byte(fmt.Sprintf("%s %d\n",
			strings.Join(fieldValues, ";"),
			record.cnt.ValueByName(c.countField),
		)))
	}
	writer.Flush()

	return outFile, nil
}
