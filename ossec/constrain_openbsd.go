package ossec

import "golang.org/x/sys/unix"

func PledgePromises(promises string) error {
	return unix.PledgePromises(promises)
}
