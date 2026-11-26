// The install command and enroll.conf of the add device flow, as the
// classic enrollment page prints them.

export const installCommand = (publicURL: string, token?: string) => (token ? `curl -fsSL ${publicURL}/install.sh | sudo LIMDM_TOKEN=${token} sh` : `curl -fsSL ${publicURL}/install.sh | sudo sh`)

export const enrollConf = (agentURL: string, fingerprint: string, token: string) =>
  [`server = "${agentURL}"`, `fingerprint = "${fingerprint}"`, `token = "${token}"`, 'allow_scripts = false', 'allow_remote_shell = false'].join('\n')
