package db

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestTaskSpeedProfileDefaultUpdateAndInvalid(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { d.Close() })
	suffix := time.Now().UnixNano()

	task, err := d.CreateTaskWithOptions(fmt.Sprintf("speed-default-%d", suffix), "goal", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()
	if task.SpeedProfile != SpeedProfileStandard {
		t.Fatalf("created profile=%q, want standard", task.SpeedProfile)
	}
	if got, err := d.TaskSpeedProfile(task.ID); err != nil || got != SpeedProfileStandard {
		t.Fatalf("TaskSpeedProfile=%q,%v want standard", got, err)
	}

	stealth, err := d.CreateTaskWithOptions(fmt.Sprintf("speed-stealth-%d", suffix), "goal", TaskCreateOptions{SpeedProfile: SpeedProfileStealth})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(stealth.ID) }()
	if got, err := d.TaskSpeedProfile(stealth.ID); err != nil || got != SpeedProfileStealth {
		t.Fatalf("explicit create profile=%q,%v want stealth", got, err)
	}

	bad := "turbo"
	if _, err := d.CreateTaskWithOptions(fmt.Sprintf("speed-bad-%d", suffix), "goal", TaskCreateOptions{SpeedProfile: bad}); !errors.Is(err, ErrTaskSpeedProfileInvalid) {
		t.Fatalf("invalid create error=%v, want %v", err, ErrTaskSpeedProfileInvalid)
	}
	if _, err := d.UpdateTask(task.ID, TaskPatch{SpeedProfile: &bad}); !errors.Is(err, ErrTaskSpeedProfileInvalid) {
		t.Fatalf("invalid update error=%v, want %v", err, ErrTaskSpeedProfileInvalid)
	}

	for _, want := range []string{SpeedProfileUnbound, SpeedProfileCareful} {
		updated, err := d.UpdateTask(task.ID, TaskPatch{SpeedProfile: &want})
		if err != nil || updated == nil || updated.SpeedProfile != want {
			t.Fatalf("update to %s = %+v, %v", want, updated, err)
		}
		if got, err := d.TaskSpeedProfile(task.ID); err != nil || got != want {
			t.Fatalf("persisted profile=%q,%v want %s", got, err, want)
		}
	}
	// A patch that omits the profile leaves it unchanged.
	name := "renamed speed task"
	if _, err := d.UpdateTask(task.ID, TaskPatch{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.TaskSpeedProfile(task.ID); got != SpeedProfileCareful {
		t.Fatalf("profile after rename=%q, want careful", got)
	}
	profiles, err := d.TaskSpeedProfiles()
	if err != nil || profiles[task.ID] != SpeedProfileCareful || profiles[stealth.ID] != SpeedProfileStealth {
		t.Fatalf("TaskSpeedProfiles=%v,%v", profiles, err)
	}
}
