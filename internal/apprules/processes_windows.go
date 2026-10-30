//go:build windows

package apprules

import (
	"sort"

	"golang.org/x/sys/windows"
)

// Process is one running process offered by the UI's process picker.
type Process struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// ListProcesses enumerates running processes with their image paths, for the
// "add from running process" picker. Processes whose image path cannot be
// read (protected system processes, permission boundaries) are skipped rather
// than failing the whole listing.
func ListProcesses() ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var out []Process
	var entry windows.ProcessEntry32
	entry.Size = uint32(len(entry.ExeFile))
	err = windows.Process32First(snap, &entry)
	for err == nil {
		if path, perr := processImagePath(entry.ProcessID); perr == nil && path != "" {
			out = append(out, Process{
				PID:  entry.ProcessID,
				Name: windows.UTF16ToString(entry.ExeFile[:]),
				Path: path,
			})
		}
		err = windows.Process32Next(snap, &entry)
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func processImagePath(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	var buf [32768]uint16 // extended-length path, well past MAX_PATH
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}
