package internal

import (
	"context"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flamegraph"
	"ior/internal/types"
	"testing"
	"time"
)

// Test that comm names are properly propagated across syscalls
func TestCommPropagation(t *testing.T) {
	td := makeCommPropagationTestData(t)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inCh := make(chan []byte)
	outCh := make(chan *event.Pair)

	el := newEventLoop()
	el.printCb = func(ev *event.Pair) { outCh <- ev }
	go el.run(ctx, inCh)

	go func() {
		for _, raw := range td.rawTracepoints {
			t.Log("Sending raw tracepoint", raw, "simulating BPF sending this")
			inCh <- raw
			// Small delay to simulate real BPF event timing
			time.Sleep(time.Microsecond)
		}
	}()
	
	for _, validate := range td.validates {
		ep := <-outCh
		t.Log("Received", ep)
		validate(t, el, ep)
	}
	
	// Give a small delay to ensure any unexpected events would have arrived
	time.Sleep(10 * time.Millisecond)
	select {
	case x := <-outCh:
		t.Errorf("Expected no more events but got '%v'", x)
	default:
	}
}

func makeCommPropagationTestData(t *testing.T) (td testData) {
	fd := int32(42)
	tid := uint32(defaultTid)
	commName := "testapp"
	
	// Step 1: OpenEvent establishes comm name
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, tid)
	copy(openEnterEv.Filename[:], "comm_test.txt")
	// Clear the comm buffer first to avoid leftover characters
	for i := range openEnterEv.Comm {
		openEnterEv.Comm[i] = 0
	}
	copy(openEnterEv.Comm[:], commName)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)
	
	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, tid)
	openExitEv.Ret = int64(fd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)
	
	// Validate open establishes comm name
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// Verify comm name is recorded
		verifyCommName(t, el, tid, commName)
		// Verify event has comm name
		if ep.Comm != commName {
			t.Errorf("Expected comm name '%s' but got '%s'", commName, ep.Comm)
		}
	})
	
	// Step 2: Read syscall should get comm name automatically
	_, readEnterBytes := makeEnterFdEvent(t, defaulTime+200, defaultPid, tid, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readEnterBytes)
	
	_, readExitBytes := makeExitFdEvent(t, defaulTime+300, defaultPid, tid, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readExitBytes)
	
	// Validate read has comm name
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.Comm != commName {
			t.Errorf("Expected read to have comm name '%s' but got '%s'", commName, ep.Comm)
		}
	})
	
	// Step 3: Stat syscall should also get comm name
	_, pathEnterBytes := makeEnterPathEvent(t, defaulTime+400, defaultPid, tid, "/etc/passwd", types.SYS_ENTER_NEWSTAT)
	td.rawTracepoints = append(td.rawTracepoints, pathEnterBytes)
	
	_, pathExitBytes := makeExitNullEvent(t, defaulTime+500, defaultPid, tid, types.SYS_EXIT_NEWSTAT)
	td.rawTracepoints = append(td.rawTracepoints, pathExitBytes)
	
	// Validate stat has comm name
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.Comm != commName {
			t.Errorf("Expected stat to have comm name '%s' but got '%s'", commName, ep.Comm)
		}
	})
	
	// Step 4: Different thread without open should not have comm name
	differentTid := tid + 100
	_, diffReadEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, differentTid, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, diffReadEnterBytes)
	
	_, diffReadExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, differentTid, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, diffReadExitBytes)
	
	// Validate different thread doesn't have comm name
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.Comm != "" {
			t.Errorf("Expected no comm name for different thread but got '%s'", ep.Comm)
		}
		// Verify comm map doesn't have entry for this tid
		if _, ok := el.comms[differentTid]; ok {
			t.Errorf("Expected no comm entry for tid %d but one was found", differentTid)
		}
	})
	
	return td
}

// Test filter behavior for each event type
func TestEventTypeFiltering(t *testing.T) {
	// Test with comm filter = "nginx" and path filter = "/var/log"
	testTable := []struct {
		name        string
		commFilter  string
		pathFilter  string
		makeTestData func(t *testing.T, commFilter, pathFilter string) testData
	}{
		{
			name:       "OpenEventFiltering",
			commFilter: "nginx",
			pathFilter: "/var/log",
			makeTestData: makeOpenEventFilterTestData,
		},
		{
			name:       "PathEventFiltering",
			commFilter: "",
			pathFilter: "/etc",
			makeTestData: makePathEventFilterTestData,
		},
		{
			name:       "NameEventFiltering",
			commFilter: "",
			pathFilter: "/tmp",
			makeTestData: makeNameEventFilterTestData,
		},
		{
			name:       "FdEventFiltering",
			commFilter: "apache",
			pathFilter: "/var/www",
			makeTestData: makeFdEventFilterTestData,
		},
	}
	
	for _, tt := range testTable {
		t.Run(tt.name, func(t *testing.T) {
			td := tt.makeTestData(t, tt.commFilter, tt.pathFilter)
			
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			inCh := make(chan []byte)
			outCh := make(chan *event.Pair)

			el := newEventLoopWithFilter(tt.commFilter, tt.pathFilter)
			el.printCb = func(ev *event.Pair) { outCh <- ev }
			go el.run(ctx, inCh)

			go func() {
				for _, raw := range td.rawTracepoints {
					inCh <- raw
					time.Sleep(time.Microsecond)
				}
			}()
			
			for _, validate := range td.validates {
				select {
				case ep := <-outCh:
					t.Log("Received", ep)
					validate(t, el, ep)
				case <-time.After(100 * time.Millisecond):
					// No event expected (filtered out)
					validate(t, el, nil)
				}
			}
		})
	}
}

func makeOpenEventFilterTestData(t *testing.T, commFilter, pathFilter string) (td testData) {
	// Test 1: Event that matches both filters (should pass)
	openEnterEv1, openEnterBytes1 := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv1.Filename[:], "/var/log/nginx/access.log")
	// Clear the comm buffer first to avoid leftover characters
	for i := range openEnterEv1.Comm {
		openEnterEv1.Comm[i] = 0
	}
	copy(openEnterEv1.Comm[:], "nginx-worker")
	openEnterBytes1, _ = openEnterEv1.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes1)
	
	openExitEv1, openExitBytes1 := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv1.Ret = 42
	openExitBytes1, _ = openExitEv1.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes1)
	
	// Should receive this event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep == nil {
			t.Error("Expected event to pass filter but it was filtered out")
		}
	})
	
	// Test 2: Event with wrong comm (should be filtered)
	openEnterEv2, openEnterBytes2 := makeEnterOpenEvent(t, defaulTime+200, defaultPid, defaultTid+1)
	copy(openEnterEv2.Filename[:], "/var/log/apache/error.log")
	for i := range openEnterEv2.Comm {
		openEnterEv2.Comm[i] = 0
	}
	copy(openEnterEv2.Comm[:], "apache")
	openEnterBytes2, _ = openEnterEv2.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes2)
	
	openExitEv2, openExitBytes2 := makeExitOpenEvent(t, defaulTime+300, defaultPid, defaultTid+1)
	openExitEv2.Ret = 43
	openExitBytes2, _ = openExitEv2.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes2)
	
	// Should NOT receive this event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep != nil {
			t.Error("Expected event to be filtered out but it passed")
		}
	})
	
	// Test 3: Event with wrong path (should be filtered)
	openEnterEv3, openEnterBytes3 := makeEnterOpenEvent(t, defaulTime+400, defaultPid, defaultTid+2)
	copy(openEnterEv3.Filename[:], "/etc/nginx/nginx.conf")
	for i := range openEnterEv3.Comm {
		openEnterEv3.Comm[i] = 0
	}
	copy(openEnterEv3.Comm[:], "nginx")
	openEnterBytes3, _ = openEnterEv3.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes3)
	
	openExitEv3, openExitBytes3 := makeExitOpenEvent(t, defaulTime+500, defaultPid, defaultTid+2)
	openExitEv3.Ret = 44
	openExitBytes3, _ = openExitEv3.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes3)
	
	// Should NOT receive this event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep != nil {
			t.Error("Expected event to be filtered out but it passed")
		}
	})
	
	return td
}

func makePathEventFilterTestData(t *testing.T, commFilter, pathFilter string) (td testData) {
	// Test 1: Path event that matches filter (should pass)
	_, pathEnterBytes1 := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, "/etc/passwd", types.SYS_ENTER_NEWSTAT)
	td.rawTracepoints = append(td.rawTracepoints, pathEnterBytes1)
	
	_, pathExitBytes1 := makeExitNullEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_NEWSTAT)
	td.rawTracepoints = append(td.rawTracepoints, pathExitBytes1)
	
	// Should receive this event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep == nil {
			t.Error("Expected path event to pass filter but it was filtered out")
		}
	})
	
	// Test 2: Path event that doesn't match filter (should be filtered)
	_, pathEnterBytes2 := makeEnterPathEvent(t, defaulTime+200, defaultPid, defaultTid+1, "/var/log/messages", types.SYS_ENTER_NEWSTAT)
	td.rawTracepoints = append(td.rawTracepoints, pathEnterBytes2)
	
	_, pathExitBytes2 := makeExitNullEvent(t, defaulTime+300, defaultPid, defaultTid+1, types.SYS_EXIT_NEWSTAT)
	td.rawTracepoints = append(td.rawTracepoints, pathExitBytes2)
	
	// Should NOT receive this event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep != nil {
			t.Error("Expected path event to be filtered out but it passed")
		}
	})
	
	return td
}

func makeNameEventFilterTestData(t *testing.T, commFilter, pathFilter string) (td testData) {
	// Test 1: Rename with oldname matching filter (should pass)
	_, nameEnterBytes1 := makeEnterNameEvent(t, defaulTime, defaultPid, defaultTid, "/tmp/oldfile.txt", "/home/user/newfile.txt", types.SYS_ENTER_RENAME)
	td.rawTracepoints = append(td.rawTracepoints, nameEnterBytes1)
	
	_, nameExitBytes1 := makeExitNullEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_RENAME)
	td.rawTracepoints = append(td.rawTracepoints, nameExitBytes1)
	
	// Should receive this event (oldname matches)
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep == nil {
			t.Error("Expected name event to pass filter (oldname match) but it was filtered out")
		}
	})
	
	// Test 2: Rename with newname matching filter (should pass)
	_, nameEnterBytes2 := makeEnterNameEvent(t, defaulTime+200, defaultPid, defaultTid+1, "/home/user/file.txt", "/tmp/movedfile.txt", types.SYS_ENTER_RENAME)
	td.rawTracepoints = append(td.rawTracepoints, nameEnterBytes2)
	
	_, nameExitBytes2 := makeExitNullEvent(t, defaulTime+300, defaultPid, defaultTid+1, types.SYS_EXIT_RENAME)
	td.rawTracepoints = append(td.rawTracepoints, nameExitBytes2)
	
	// Should receive this event (newname matches)
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep == nil {
			t.Error("Expected name event to pass filter (newname match) but it was filtered out")
		}
	})
	
	// Test 3: Rename with neither name matching (should be filtered)
	_, nameEnterBytes3 := makeEnterNameEvent(t, defaulTime+400, defaultPid, defaultTid+2, "/home/user/doc.txt", "/home/user/document.txt", types.SYS_ENTER_RENAME)
	td.rawTracepoints = append(td.rawTracepoints, nameEnterBytes3)
	
	_, nameExitBytes3 := makeExitNullEvent(t, defaulTime+500, defaultPid, defaultTid+2, types.SYS_EXIT_RENAME)
	td.rawTracepoints = append(td.rawTracepoints, nameExitBytes3)
	
	// Should NOT receive this event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep != nil {
			t.Error("Expected name event to be filtered out but it passed")
		}
	})
	
	return td
}

func makeFdEventFilterTestData(t *testing.T, commFilter, pathFilter string) (td testData) {
	fd := int32(42)
	
	// First establish comm name and file with open
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], "/var/www/index.html")
	// Clear the comm buffer first to avoid leftover characters
	for i := range openEnterEv.Comm {
		openEnterEv.Comm[i] = 0
	}
	copy(openEnterEv.Comm[:], "apache2")
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)
	
	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(fd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)
	
	// Open should pass filters
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep == nil {
			t.Error("Expected open event to pass filter but it was filtered out")
		}
	})
	
	// Test 1: FdEvent (read) that should pass filters
	_, readEnterBytes := makeEnterFdEvent(t, defaulTime+200, defaultPid, defaultTid, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readEnterBytes)
	
	_, readExitBytes := makeExitFdEvent(t, defaulTime+300, defaultPid, defaultTid, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readExitBytes)
	
	// Should receive this event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep == nil {
			t.Error("Expected fd event to pass filter but it was filtered out")
		}
	})
	
	// Test 2: FdEvent from different process without matching comm (should be filtered)
	// Note: In real scenario, this FD wouldn't be valid for another process, but for testing...
	_, readEnterBytes2 := makeEnterFdEvent(t, defaulTime+400, defaultPid+1, defaultTid+100, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readEnterBytes2)
	
	_, readExitBytes2 := makeExitFdEvent(t, defaulTime+500, defaultPid+1, defaultTid+100, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readExitBytes2)
	
	// Should NOT receive this event (no comm name established for this tid)
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep != nil {
			t.Error("Expected fd event to be filtered out but it passed")
		}
	})
	
	return td
}

// Test comm filter enable/disable functionality
func TestCommFilterToggle(t *testing.T) {
	// Test scenario: Same events with comm filter enabled vs disabled
	fd := int32(42)
	tid := uint32(defaultTid)
	
	// Create test data
	var rawTracepoints [][]byte
	
	// FdEvent without prior OpenEvent to establish comm
	_, fdEnterBytes := makeEnterFdEvent(t, defaulTime, defaultPid, tid, fd, types.SYS_ENTER_READ)
	rawTracepoints = append(rawTracepoints, fdEnterBytes)
	
	_, fdExitBytes := makeExitFdEvent(t, defaulTime+100, defaultPid, tid, fd, types.SYS_EXIT_READ)
	rawTracepoints = append(rawTracepoints, fdExitBytes)
	
	// Test 1: With comm filter disabled (should receive event)
	t.Run("CommFilterDisabled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		inCh := make(chan []byte)
		outCh := make(chan *event.Pair)

		// Create eventloop without comm filter
		el := &eventLoop{
			filter: &eventFilter{
				commFilterEnable: false,
			},
			enterEvs:      make(map[uint32]*event.Pair),
			files:         make(map[int32]file.File),
			comms:         make(map[uint32]string),
			prevPairTimes: make(map[uint32]uint64),
			printCb:       func(ep *event.Pair) { outCh <- ep },
			flamegraph:    flamegraph.New(),
			done:          make(chan struct{}),
		}
		go el.run(ctx, inCh)

		go func() {
			for _, raw := range rawTracepoints {
				inCh <- raw
				time.Sleep(time.Microsecond)
			}
		}()
		
		select {
		case ep := <-outCh:
			t.Log("Received event with comm filter disabled:", ep)
			// Good, we received the event
		case <-time.After(100 * time.Millisecond):
			t.Error("Expected to receive event with comm filter disabled but got nothing")
		}
	})
	
	// Test 2: With comm filter enabled (should NOT receive event)
	t.Run("CommFilterEnabled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		inCh := make(chan []byte)
		outCh := make(chan *event.Pair)

		// Create eventloop with comm filter enabled
		el := &eventLoop{
			filter: &eventFilter{
				commFilterEnable: true,
				commFilter:       "test",
			},
			enterEvs:      make(map[uint32]*event.Pair),
			files:         make(map[int32]file.File),
			comms:         make(map[uint32]string),
			prevPairTimes: make(map[uint32]uint64),
			printCb:       func(ep *event.Pair) { outCh <- ep },
			flamegraph:    flamegraph.New(),
			done:          make(chan struct{}),
		}
		go el.run(ctx, inCh)

		go func() {
			for _, raw := range rawTracepoints {
				inCh <- raw
				time.Sleep(time.Microsecond)
			}
		}()
		
		select {
		case ep := <-outCh:
			t.Error("Expected no event with comm filter enabled but got:", ep)
		case <-time.After(100 * time.Millisecond):
			t.Log("Good, no event received with comm filter enabled")
			// Expected behavior
		}
	})
}