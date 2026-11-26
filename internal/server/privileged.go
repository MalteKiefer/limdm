package server

import "context"

// helpdeskAdminAccount is shown when the helpdesk role targets an account
// that can reach root. The agent enforces the same rule with its own view of
// groups and sudoers; this check only uses the last inventory.
const helpdeskAdminAccount = "The helpdesk role cannot change accounts with admin rights (uid 0, sudo, wheel or admin group)."

// privilegedShellAccount is shown when a remote shell would open as an
// account with admin rights while root sessions are not allowed.
const privilegedShellAccount = "Accounts with admin rights (uid 0, sudo, wheel or admin group) need root sessions allowed in the settings."

// accountPrivileged reports whether the device's last inventory lists the
// account with uid 0 or admin rights (sudo, wheel or admin group).
func (s *Server) accountPrivileged(ctx context.Context, deviceID, name string) bool {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices d,
		jsonb_array_elements(coalesce(d.inventory->'accounts', '[]'::jsonb)) a
		WHERE d.id=$1 AND a->>'name'=$2 AND (coalesce((a->>'admin')::boolean, false) OR a->>'uid' = '0'))`, deviceID, name).Scan(&ok)
	return err == nil && ok
}
