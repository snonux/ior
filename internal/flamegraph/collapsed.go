package flamegraph

import (
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/zstd"
)

type Collapsed struct {
	iorFile    string
	fields     []string
	countField string
}

func NewCollapsed(iorFile string, fields []string, countField string) Collapsed {
	return Collapsed{iorFile: iorFile, fields: fields, countField: countField}
}

// TODO: Write into collapsed.zst (zstd compressed) file
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
		writer.Write([]byte(fmt.Sprintf("%s = %d\n",
			strings.Join(fieldValues, ";"),
			record.cnt.ValueByName(c.countField),
		)))
	}
	writer.Flush()

	return outFile, nil
}
