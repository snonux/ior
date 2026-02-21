package types

// Trace IDs for name_to_handle_at are not generated because the tracepoint is
// ignored by default, but tests still need stable values.
const (
	SYS_ENTER_NAME_TO_HANDLE_AT TraceId = 2001
	SYS_EXIT_NAME_TO_HANDLE_AT  TraceId = 2000
)

func init() {
	traceId2String[SYS_ENTER_NAME_TO_HANDLE_AT] = "enter_name_to_handle_at"
	traceId2String[SYS_EXIT_NAME_TO_HANDLE_AT] = "exit_name_to_handle_at"

	traceId2Name[SYS_ENTER_NAME_TO_HANDLE_AT] = "name_to_handle_at"
	traceId2Name[SYS_EXIT_NAME_TO_HANDLE_AT] = "name_to_handle_at"
}
