package store

import "strings"
// map key = string value = bool
var CommWhiteListed = map[string]bool{
	"systemd":	true,
	"rsyslogd":	true,
	"journald":	true,
	"dockerd":	true,
	"sshd":		true,
	"sudo":		true,
	"login":	true,
	"ThreadPoolForeg":	true,
	"CompositorTileW":	true,
	"Chrome_IOThread":	true,
	"chrome":	true,
	"firefox":	true,
	"brave":	true,
	"zsh":		true,
	"tracker-miner-f":	true,
	"tracker-extract":	true,
	"CacheThread_Blo":	true,
}

var PathWhiteListed = []string{
	"/dev/",
	"/proc/",
	"/sys/",
	"/var/log/",
	"/home/laurentiu/.cache",
	"/bin",
	"/home/laurentiu/.local/share/tracker3/",
}
var sensitivePaths = []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		".ssh/id_rsa",
		".ssh/id_ed25519",
}
func IsCommWhiteListed(comm string) bool{
	cleanComm := strings.TrimSpace(strings.Trim(comm,"\x00"))
	return CommWhiteListed[cleanComm]
}
func IsPathWhiteListed(path string) bool{
	for _,prefix := range PathWhiteListed{
		if strings.HasPrefix(path,prefix){
			return true
		}
	}
	return false
}
func IsSensitivePath(filename string) bool{
	for _,path := range sensitivePaths{
		if strings.Contains(filename,path){
			return true
		}
	}
	return false

}




