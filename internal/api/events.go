package api

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Agent events are English lines ("declarations updated (token 42)") that
// the agent writes from the formats below and sends with its check in
// (CheckinRequest.Events). ParseEvent finds the key and the parameters of a
// line again, also for events of older agents, so the console and the
// desktop tools show the event in the reader's language: the server
// catalogs translate the English format (internal/server/i18n*.go) and
// FormatEvent fills it. Keys are stable; a changed English text keeps its key.
// TestEventFormatsComplete (internal/agent) checks that every literal format
// of the agent is here.

// EventFormats are the English formats of agent events by key; %s, %d and
// %v take one parameter each, in order.
var EventFormats = map[string]string{
	"of_requested_by":                                  "%s of %s requested by %s",
	"of_requested_by_failed":                           "%s of %s requested by %s failed: %v",
	"luks_volume_bound_to_the_tpm":                     "LUKS volume %s bound to the TPM (PCR %s)",
	"added_to_group":                                   "added %s to group %s",
	"added_flatpak_remote":                             "added Flatpak remote %s",
	"added_package_source":                             "added package source %s",
	"adding_flatpak_remote_failed":                     "adding Flatpak remote %s failed: %v",
	"agent_update_to_did_not_complete":                 "agent update to %s did not complete; it will be offered again",
	"agent_update_to_failed":                           "agent update to %s failed: %v",
	"agent_update_to_rolled_back_to":                   "agent update to %s rolled back to %s",
	"agent_updated_from_to":                            "agent updated from %s to %s",
	"autoremove":                                       "autoremove: %s",
	"boot_loader_password_configuration_updated":       "boot loader password configuration updated",
	"branding":                                         "branding: %v",
	"cannot_lock_the_session_of_no":                    "cannot lock the %s session of %s: no logind aware locker and no swaylock or i3lock",
	"certificate_renewal_failed":                       "certificate renewal failed: %v",
	"client_certificate_renewed":                       "client certificate renewed",
	"command_executed_error":                           "command %d (%s) executed, error=%v",
	"command_refused":                                  "command %d (%s) refused: %v",
	"command_signing_key_pinned_unsigned_commands":     "command signing key pinned; unsigned commands are refused from now on",
	"command_signing_key_rolled_over_to":               "command signing key rolled over to the key announced by the pinned one",
	"company_account_of_confirmed_in_the":              "company account of %s confirmed in the session",
	"created_local_user_admin":                         "created local user %s (admin %v)",
	"created_local_user_declared":                      "created local user %s (declared)",
	"created_user":                                     "created user %s (%s)",
	"declarations_updated_token":                       "declarations updated (token %s)",
	"deleted_user_home_kept":                           "deleted user %s (home kept %v)",
	"device_locked_ended":                              "device locked: ended %s",
	"device_locked_no_server_contact_for":              "device locked: no server contact for more than %d hours",
	"device_unlocked_server_reachable_again":           "device unlocked: server reachable again",
	"device_wiped":                                     "device wiped",
	"wipe_restart_scheduled_at":                        "wipe restart scheduled at %s",
	"wipe_restart_failed":                              "wipe restart failed: %s: %v",
	"wipe_restart_accepted_waiting":                    "wipe restart: %s accepted, waiting %s",
	"wipe_restart_failed_still_running":                "wipe restart failed: the device is still running, power it off",
	"disabled":                                         "disabled %s",
	"disabled_flatpak_remote":                          "disabled Flatpak remote %s (%s)",
	"enabled":                                          "enabled %s",
	"enabled_flatpak_remote":                           "enabled Flatpak remote %s (%s)",
	"escrow_requests":                                  "escrow requests: %v",
	"firewall_rule_removed_by_command":                 "firewall rule removed by command: %s",
	"firewall_rule_removed_by_policy":                  "firewall rule removed by policy: %s",
	"firewall_rule_removed":                            "firewall rule removed: %s",
	"firewall_nftables_table_inet_limdm_loaded":        "firewall: nftables table inet limdm loaded",
	"granted_admin_to":                                 "granted admin to %s",
	"hostname_changed_from_to_source":                  "hostname changed from %s to %s (source %s)",
	"imported_openvpn_profile":                         "imported OpenVPN profile %s",
	"installed_flatpak":                                "installed %s (Flatpak %s)",
	"installed_packages":                               "installed %s (packages %s)",
	"installed":                                        "installed %v",
	"installed_cups_for_the_printer_declaration":       "installed CUPS for the printer declaration",
	"installed_pam_oidc_login":                         "installed PAM OIDC login",
	"installed_flatpak2":                               "installed flatpak %s",
	"installed_missing_tools":                          "installed missing tools %v",
	"installed_osquery":                                "installed osquery %s",
	"installed_uploaded":                               "installed uploaded %s %s (%s)",
	"installing_failed":                                "installing %s failed: %v",
	"installing_agent":                                 "installing agent %s",
	"installing_missing_tools_failed":                  "installing missing tools %v failed: %v",
	"keeping_the_lock_screen_enabled":                  "keeping the lock screen enabled: %v",
	"kept_no_longer_declared":                          "kept %s (no longer declared): %v",
	"local_password_of_locked_until_the":               "local password of %s locked until the next SSO confirmation",
	"local_password_of_unlocked":                       "local password of %s unlocked",
	"local_password_of_unlocked_desktop_login":         "local password of %s unlocked: desktop login switched off",
	"local_user_has_uid_declared_not":                  "local user %s has uid %s, declared %d: not renumbered",
	"lock_screen_lockdown":                             "lock screen lockdown: %v",
	"locked_local_user_declared":                       "locked local user %s (declared)",
	"locked_local_user_no_longer_declared":             "locked local user %s (no longer declared)",
	"locked_removed_user":                              "locked removed user %s",
	"locked_user":                                      "locked user %s",
	"locking_the_session_of_failed":                    "locking the session of %s failed: %v",
	"lost_mode_activated":                              "lost mode activated",
	"lost_mode_ended":                                  "lost mode ended",
	"network_certificate_issued_valid_until":           "network certificate issued, valid until %s",
	"network_certificate_request_failed":               "network certificate request failed: %v",
	"network_certificate_unusable":                     "network certificate unusable: %v",
	"network_profiles_updated_managed":                 "network profiles updated (%d managed)",
	"offline_lock":                                     "offline lock: %v",
	"package_source_disabled":                          "package source %s disabled",
	"package_source_enabled_again":                     "package source %s enabled again",
	"package_sources_updated":                          "package sources updated",
	"packages_held":                                    "packages held: %v",
	"packages_released":                                "packages released: %v",
	"password_of_reset":                                "password of %s reset",
	"printer_removed":                                  "printer %s removed",
	"printer_set_up":                                   "printer %s set up",
	"reboot_scheduled_at_after_updates":                "reboot scheduled at %s after updates",
	"recovery_key_created_for_from_the":                "recovery key created for %s from the desktop (uid %d)",
	"recovery_key_for_escrowed":                        "recovery key for %s escrowed",
	"recovery_key_for_rotated_waiting_for":             "recovery key for %s rotated, waiting for escrow",
	"refused_a_command_key_rollover_keeping":           "refused a command key rollover: %v; keeping the pinned key",
	"refused_new_device_cas_from_the":                  "refused new device CAs from the server: %v",
	"refused_new_device_cas_none_trusted":              "refused new device CAs from the server: none of them is trusted now",
	"refused_the_from_the_server":                      "refused the %s from the server: %v",
	"releasing_local_passwords":                        "releasing local passwords: %v",
	"remediated":                                       "remediated %s",
	"remediation_failed":                               "remediation %s failed: %v",
	"remote_shell_as_opened_by":                        "remote shell as %s opened by %s",
	"remote_shell_as_opened_by_ended":                  "remote shell as %s opened by %s ended: %v",
	"removed_on_it_s_request":                          "removed %s %s on IT's request",
	"removed_flatpak":                                  "removed %s (Flatpak %s)",
	"removed_no_longer_declared":                       "removed %s (no longer declared)",
	"removed_packages":                                 "removed %s (packages %s)",
	"removed_from_group":                               "removed %s from group %s",
	"removed":                                          "removed %v",
	"removed_pam_oidc_login":                           "removed PAM OIDC login",
	"removed_flatpak2":                                 "removed flatpak %s",
	"removing_previous_recovery_key_of":                "removing previous recovery key of %s: %v",
	"removing_the_lock_screen_lockdown":                "removing the lock screen lockdown: %v",
	"removing_the_package_source_of":                   "removing the package source of %s: %v",
	"renewed_certificate_unusable_keeping_the_current": "renewed certificate unusable, keeping the current one: %v",
	"restart_postponed_to_by_of":                       "restart postponed to %s by %s (%d of %d)",
	"revoked_admin_from":                               "revoked admin from %s",
	"shell_of_set_to":                                  "shell of %s set to %s",
	"snap_refresh":                                     "snap refresh: %s",
	"software_stores_read_only":                        "software stores read only: %v",
	"started_the_idle_screen_lock_for":                 "started the idle screen lock for %s (%s session)",
	"store_lock":                                       "store lock: %v",
	"storing_network_certificate_failed":               "storing network certificate failed: %v",
	"storing_renewed_certificate_failed":               "storing renewed certificate failed: %v",
	"storing_the_device_cas_failed":                    "storing the device CAs failed: %v",
	"tamper":                                           "tamper: %s",
	"the_server_sent_a_different_command":              "the server sent a different command signing key; keeping the pinned one",
	"trusted_ca_certificates_updated_managed":          "trusted CA certificates updated (%d managed)",
	"trusted_device_cas_updated":                       "trusted device CAs updated (%d)",
	"unlocked_local_user_declared":                     "unlocked local user %s (declared)",
	"unlocked_user":                                    "unlocked user %s",
	"updates_updated":                                  "updates (%s): %d updated",
	"updates":                                          "updates (%s): %s",
	"updates_no_updates":                               "updates (%s): no updates",
	"workload_error":                                   "workload %s %s (%s): %s, error=%v",
	"wrote":                                            "wrote %s",
}

type eventPattern struct {
	key     string
	re      *regexp.Regexp
	literal int
}

var eventVerb = regexp.MustCompile(`%(?:\[(\d+)\])?[sdv]`)

var eventPatterns = sync.OnceValue(func() []eventPattern {
	out := make([]eventPattern, 0, len(EventFormats))
	for k, f := range EventFormats {
		var b strings.Builder
		b.WriteString("^")
		last := 0
		for _, m := range eventVerb.FindAllStringIndex(f, -1) {
			b.WriteString(regexp.QuoteMeta(f[last:m[0]]))
			b.WriteString("(.*?)")
			last = m[1]
		}
		b.WriteString(regexp.QuoteMeta(f[last:]) + "$")
		out = append(out, eventPattern{k, regexp.MustCompile(b.String()), len(eventVerb.ReplaceAllString(f, ""))})
	}
	// the most specific format wins: "...: none of them is trusted now" before "...: %v"
	slices.SortFunc(out, func(a, b eventPattern) int {
		if a.literal != b.literal {
			return b.literal - a.literal
		}
		return strings.Compare(a.key, b.key)
	})
	return out
})

// ParseEvent returns the key and parameters of an event text (without its
// time stamp), or "" when no format matches.
func ParseEvent(text string) (key string, params []string) {
	for _, p := range eventPatterns() {
		if m := p.re.FindStringSubmatch(text); m != nil {
			return p.key, m[1:]
		}
	}
	return "", nil
}

// FormatEvent fills a format (an entry of EventFormats or its translation)
// with params: %s, %d and %v take the next parameter, %[n]s the n-th, so a
// translation may reorder them. A missing parameter stays empty.
func FormatEvent(format string, params []string) string {
	next := 0
	return eventVerb.ReplaceAllStringFunc(format, func(v string) string {
		i := next
		if m := eventVerb.FindStringSubmatch(v); m[1] != "" {
			n, _ := strconv.Atoi(m[1])
			i = n - 1
		} else {
			next++
		}
		if i < 0 || i >= len(params) {
			return ""
		}
		return params[i]
	})
}
