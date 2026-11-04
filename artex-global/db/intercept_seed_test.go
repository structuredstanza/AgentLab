package db

import (
	"regexp"
	"testing"
)

// The built-in "deletion endpoint path" rule matches the entire tool_input JSON string, so the test cases are supplied directly in
// Given in JSON form, consistent with the subject that the Interceptor actually receives.
func TestDeleteEndpointPathPattern(t *testing.T) {
	re := regexp.MustCompile(deleteEndpointPathPattern)

	hit := []string{
		`{"command":"curl -s 'http://t.com/api/user/delete?id=1'"}`,    // GET hits the delete interface
		`{"command":"curl -X POST http://t.com/admin/delete -d id=1"}`, // POST hits the delete interface
		`{"command":"curl 'http://t.com/api/deleteAll'"}`,
		`{"command":"curl 'http://t.com/api/delete_user?id=1'"}`,
		`{"command":"curl 'http://t.com/api/delete-user?id=1'"}`,
		`{"url":"http://t.com/api/remove?id=1"}`,
		`{"command":"curl http://t.com/files/unlink/3"}`,
		`{"command":"curl http://t.com/api/del?id=2"}`,
		`{"command":"curl -X POST http://t/v1/erase"}`,
		`{"command":"curl http://t/admin/destroyAll"}`, // The path rules in v1 did not allow suffixes; adding support for them here
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("should match but was allowed: %s", s)
		}
	}

	// A verb must be followed by a delimiter, so that read-only paths such as /delivery and /details are not wrongly blocked.
	miss := []string{
		`{"command":"curl 'http://t.com/api/delivery?id=1'"}`,
		`{"command":"curl 'http://t.com/order/details'"}`,
		`{"command":"curl 'http://t.com/api/delta/sync'"}`,
		`{"command":"curl 'http://t.com/user/delegate'"}`,
		`{"command":"curl 'http://delete.example.com/'"}`, // Delete verb appears in the domain name rather than the path
		`{"command":"curl 'http://t.com/remote/status'"}`,
		`{"command":"nmap -p80 10.0.0.1"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("false positive block: %s", s)
		}
	}
}

// The critical-path rule must judge only rm's own arguments. The rule is matched
// against the JSON-encoded tool input, so a line break there is the two characters
// `\` and `n` — not a newline. Both shipped versions failed on that: v3/v4 denied
// any absolute path within 60 characters of rm, and v5 walked across the `\n`
// escape. The first case is the command that was actually denied in a live run,
// where /dev/null belonged to curl.
func TestCriticalPathDeletePattern(t *testing.T) {
	re := regexp.MustCompile(criticalPathDeletePattern)

	miss := []string{
		`{"command": "cd /state/artex/tasks/9/i76; CJ=/state/artex/tasks/9/i76/cj.txt; rm -f $CJ\ncurl -s -k -c $CJ -b $CJ -o /dev/null -w \"logon:%{http_code}\\n\" -d \"username=x\" \"https://h/web/index.php?logon\"\ncat $CJ"}`,
		`{"command":"rm -f cj2.txt; curl -sk -D /dev/null https://h/"}`,
		`{"command":"rm -f a.txt && curl http://h/etc/x"}`,
		`{"command":"rm /home/minerva/tmp.txt"}`,
		`{"command":"rm -f /tmp/scan.txt"}`,
		`{"command":"cd /x; rm -f f; cat /etc/passwd"}`,
	}
	for _, s := range miss {
		if re.MatchString(s) {
			t.Errorf("false positive block: %s", s)
		}
	}

	hit := []string{
		`{"command":"rm -rf /"}`,
		`{"command":"rm -rf /etc"}`,
		`{"command":"rm -f /etc/passwd"}`,
		`{"command":"rm -rf /usr/bin"}`,
		`{"command":"rm --no-preserve-root -rf /"}`,
		`{"command":"rm -f \"/etc/hosts\""}`,
		`{"command":"rm -rf /dev/sda"}`,
		`{"command":"rm -f /var/lib/dpkg/status"}`,
		`{"command":"rm -f /root/.bashrc"}`,
		`{"command":"rm -rf /boot"}`,
		`{"command":"rm -f /sys/x"}`,
		`{"command":"rm -f /proc/self/environ"}`,
	}
	for _, s := range hit {
		if !re.MatchString(s) {
			t.Errorf("should match but was allowed: %s", s)
		}
	}
}
