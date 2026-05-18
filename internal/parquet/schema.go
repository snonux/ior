package parquet

import (
	"os"
	"strconv"
	"time"

	"ior/internal/flags"
	"ior/internal/streamrow"

	parquetgo "github.com/parquet-go/parquet-go"
)

// Record is the persisted Parquet schema for one syscall stream row.
type Record struct {
	Seq         uint64 `parquet:"seq"`
	TimeNS      uint64 `parquet:"time_ns"`
	GapNS       uint64 `parquet:"gap_ns"`
	LatencyNS   uint64 `parquet:"latency_ns"`
	Comm        string `parquet:"comm"`
	PID         uint32 `parquet:"pid"`
	TID         uint32 `parquet:"tid"`
	Syscall     string `parquet:"syscall"`
	Family      string `parquet:"family"`
	FD          int32  `parquet:"fd"`
	Ret         int64  `parquet:"ret"`
	Bytes       uint64 `parquet:"bytes"`
	File        string `parquet:"file"`
	IsError     bool   `parquet:"is_error"`
	FilterEpoch uint64 `parquet:"filter_epoch"`
}

// FileMetadata captures constant metadata written once into the parquet file.
type FileMetadata struct {
	Hostname          string
	StartedAtUnixNano uint64
	Mode              string
	IORVersion        string
}

// NewFileMetadata constructs file-level metadata for a parquet trace file,
// populating the hostname, timestamp, version, and recording mode.
func NewFileMetadata(mode string) FileMetadata {
	meta := FileMetadata{
		StartedAtUnixNano: uint64(time.Now().UnixNano()),
		Mode:              mode,
		IORVersion:        flags.Version,
	}
	if hostname, err := os.Hostname(); err == nil {
		meta.Hostname = hostname
	}
	return meta
}

// RecordFromStream converts one shared stream row into the persisted format.
func RecordFromStream(row streamrow.Row, filterEpoch uint64) Record {
	return Record{
		Seq:         row.Seq,
		TimeNS:      row.TimeNs,
		GapNS:       row.GapNs,
		LatencyNS:   row.DurationNs,
		Comm:        row.Comm,
		PID:         row.PID,
		TID:         row.TID,
		Syscall:     row.Syscall,
		Family:      row.Family,
		FD:          row.FD,
		Ret:         row.RetVal,
		Bytes:       row.Bytes,
		File:        row.FileName,
		IsError:     row.IsError,
		FilterEpoch: filterEpoch,
	}
}

func writerMetadataOptions(meta FileMetadata) []parquetgo.WriterOption {
	meta = normalizeMetadata(meta)
	options := make([]parquetgo.WriterOption, 0, 4)
	if meta.Hostname != "" {
		options = append(options, parquetgo.KeyValueMetadata("ior.hostname", meta.Hostname))
	}
	if meta.StartedAtUnixNano != 0 {
		options = append(options, parquetgo.KeyValueMetadata("ior.started_at_unix_nano", strconv.FormatUint(meta.StartedAtUnixNano, 10)))
	}
	if meta.Mode != "" {
		options = append(options, parquetgo.KeyValueMetadata("ior.mode", meta.Mode))
	}
	if meta.IORVersion != "" {
		options = append(options, parquetgo.KeyValueMetadata("ior.version", meta.IORVersion))
	}
	return options
}

func normalizeMetadata(meta FileMetadata) FileMetadata {
	if meta.IORVersion == "" {
		meta.IORVersion = flags.Version
	}
	return meta
}
