package agent

import (
	"strings"
	"testing"

	"github.com/maltekiefer/limdm/internal/api"
)

func TestTPM2EnrollArgs(t *testing.T) {
	got := strings.Join(tpm2EnrollArgs("/dev/nvme0n1p3", "/run/limdm-luks-1/0", &api.TPM2Binding{}), " ")
	want := "--unlock-key-file=/run/limdm-luks-1/0 --tpm2-device=auto --tpm2-pcrs=7 --wipe-slot=tpm2 /dev/nvme0n1p3"
	if got != want {
		t.Fatalf("\n%s\n%s", got, want)
	}
	got = strings.Join(tpm2EnrollArgs("/dev/sda2", "/k", &api.TPM2Binding{PCRs: []int{0, 7}, PIN: true}), " ")
	if !strings.Contains(got, "--tpm2-pcrs=0+7") || !strings.Contains(got, "--tpm2-with-pin=yes") || !strings.HasSuffix(got, " /dev/sda2") {
		t.Fatal(got)
	}
	a := &Agent{}
	if st, _ := runTPMBinding(a); st != na {
		t.Fatal(st)
	}
}
