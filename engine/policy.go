package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	policyTable      = "caddy_abuseguard_intel"
	policyAppliedSrc = "policy-apply"
)

// Only these jails get their ignoreip driven by the generated file. Other
// jails (including retired intel jails) keep their own configuration.
var policyJails = []string{"caddy-rate-local", "caddy-probe-h1", "caddy-probe-h2", "sshd"}

var (
	ignoreipToken = regexp.MustCompile(`^[A-Za-z0-9:._/-]+$`)
	ipv4Element   = regexp.MustCompile(`([0-9]{1,3}\.){3}[0-9]{1,3}`)
)

type policyPaths struct {
	confDir    string
	configPath string
	intelNFT   string
	allowNFT   string
	applied    string
	f2bDir     string
	f2bPolicy  string
}

// policyDiskBackup is the previous root snapshot set, restored when the
// kernel change cannot be persisted.
type policyDiskBackup struct {
	intel, allow, applied      []byte
	hadIntel, hadAllow, hadApp bool
}

// runPolicyApply is the root-only native-policy entry point. It is the only
// engine command that needs root: sync/report/enqueue remain unprivileged.
func runPolicyApply(args []string) {
	if len(args) != 0 {
		logf("policy-apply: unexpected arguments")
		os.Exit(2)
	}
	if runtime.GOOS != "linux" {
		logf("policy-apply: 仅支持 Linux。")
		os.Exit(1)
	}
	if os.Geteuid() != 0 {
		logf("policy-apply: 需要 root 权限")
		os.Exit(1)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		logf("policy-apply: 未找到 nft")
		os.Exit(1)
	}
	confDir := policyEnv("AG_CONF_DIR", "/etc/caddy-abuseguard")
	if fi, err := os.Stat(confDir); err != nil || !fi.IsDir() {
		logf("policy-apply: 配置目录不存在：%s", confDir)
		os.Exit(1)
	}
	lock, err := acquirePolicyLock(filepath.Join(confDir, "policy.lock"), 60*time.Second)
	if err != nil {
		logf("policy-apply: %v", err)
		os.Exit(1)
	}
	defer lock.Close()
	if err := applyPolicy(confDir); err != nil {
		logf("policy-apply: %v", err)
		os.Exit(1)
	}
}

func policyEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func policyPathsFor(confDir string) policyPaths {
	return policyPaths{
		confDir:    confDir,
		configPath: filepath.Join(confDir, "config.json"),
		intelNFT:   filepath.Join(confDir, "intel.nft"),
		allowNFT:   filepath.Join(confDir, "intel-allow.nft"),
		applied:    filepath.Join(confDir, "intel-applied.json"),
		f2bDir:     policyEnv("AG_F2B_JAIL_DIR", "/etc/fail2ban/jail.d"),
	}
}

func applyPolicy(confDir string) error {
	p := policyPathsFor(confDir)
	p.f2bPolicy = filepath.Join(p.f2bDir, "zzz-caddy-abuseguard-policy.local")

	work, err := os.MkdirTemp(confDir, ".policy.")
	if err != nil {
		return fmt.Errorf("无法创建策略临时目录：%w", err)
	}
	defer os.RemoveAll(work)

	// Boot starts with no kernel table: restore the root-owned last-good
	// snapshot before any config, whitelist, feed or fail2ban read can fail.
	if !nftTableExists() {
		restorePolicySnapshot(p.intelNFT)
	}

	c, err := loadConfigAt(p.configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败；未更改任何策略：%w", err)
	}

	allowData, err := formatAllowlist(c.AllowlistFile)
	if err != nil {
		return fmt.Errorf("白名单校验/导出失败；未更改任何策略：%w", err)
	}
	allow, err := loadAllowlist(c.AllowlistFile)
	if err != nil {
		return fmt.Errorf("白名单校验/导出失败；未更改任何策略：%w", err)
	}
	allowEntries := nonEmptyLines(allowData)

	// Preserve admin-managed native ignoreip per jail before the kernel change,
	// reading the effective config with the generated file moved aside so later
	// edits/removals propagate on the next apply.
	merge, err := captureNativeIgnoreip(p.f2bPolicy, allowEntries)
	if err != nil {
		return err
	}

	intelData, err := formatIntel(c)
	if err != nil {
		return fmt.Errorf("情报导出失败；保留上一次生效的策略（检查 %s/intel.txt）：%w", c.Paths.StateDir, err)
	}
	intelEntries := nonEmptyLines(intelData)
	if len(intelEntries) == 0 && policyHasElements(p) {
		// Missing feed after a non-empty policy existed is a failure, not a
		// request to wipe enforcement.
		return errors.New("情报导出为空；已有策略不会被空列表覆盖（首次安装允许空列表）。")
	}

	now := time.Now().UTC()
	intelNFT := renderIntelNFT(intelEntries, allowEntries, now)
	allowNFT := renderAllowNFT(allowEntries)
	applied := renderApplied(now, len(intelEntries), len(allowEntries))

	intelPath := filepath.Join(work, "intel.nft")
	if err := os.WriteFile(intelPath, intelNFT, 0600); err != nil {
		return fmt.Errorf("无法创建策略临时文件；未更改任何策略：%w", err)
	}
	if err := nftCheckFile(intelPath); err != nil {
		return fmt.Errorf("内核策略校验失败；未更改任何策略：%w", err)
	}

	// Back up both the live policy and the disk snapshots before changing the
	// kernel: a failed persist must restore what is actually enforced, not an
	// assumption that disk matches the running table.
	hadLive, err := captureLivePolicy(work)
	if err != nil {
		return fmt.Errorf("无法备份当前内核策略；未更改任何策略：%w", err)
	}
	backup, err := backupPolicyFiles(p)
	if err != nil {
		return fmt.Errorf("无法备份策略快照；未更改任何策略：%w", err)
	}

	if err := nftApplyFile(intelPath); err != nil {
		return fmt.Errorf("内核策略应用失败；旧策略保持不变：%w", err)
	}

	err = writeFileAtomic(p.intelNFT, intelNFT, 0640)
	if err == nil {
		err = writeFileAtomic(p.allowNFT, allowNFT, 0640)
		if err == nil {
			err = writeFileAtomic(p.applied, applied, 0640)
		}
	}
	if err != nil {
		rollbackPolicy(p, work, hadLive, backup)
		return fmt.Errorf("无法保存情报策略快照；已恢复上一次内核策略：%w", err)
	}

	f2bData := renderFail2banPolicy(c.AllowlistFile, merge)
	f2bChanged, f2bOld, hadF2B, err := prepareFail2banFile(p.f2bDir, p.f2bPolicy, f2bData)
	if err != nil {
		rollbackPolicy(p, work, hadLive, backup)
		return err
	}
	if f2bChanged {
		if err := writeFileAtomic(p.f2bPolicy, f2bData, 0644); err != nil {
			rollbackPolicy(p, work, hadLive, backup)
			return fmt.Errorf("无法写入 fail2ban ignoreip；已恢复上一次内核策略：%w", err)
		}
	}

	if exec.Command("fail2ban-client", "ping").Run() == nil {
		if f2bChanged {
			if err := exec.Command("fail2ban-client", "reload").Run(); err != nil {
				restoreFail2banFile(p.f2bPolicy, f2bOld, hadF2B)
				if rerr := exec.Command("fail2ban-client", "reload").Run(); rerr != nil {
					logf("policy-apply: 警告：fail2ban 回滚重载失败，请手动检查：%v", rerr)
				}
				rollbackPolicy(p, work, hadLive, backup)
				return fmt.Errorf("fail2ban 重载失败；已回滚内核策略和 ignoreip：%w", err)
			}
		}
		clearWhitelistedBans(allow)
	} else {
		logf("policy-apply: fail2ban 未运行；ignoreip 已更新，将在下次启动时生效。")
	}

	logf("策略已应用：%d 条情报，%d 条白名单。", len(intelEntries), len(allowEntries))
	return nil
}

// captureNativeIgnoreip merges the whitelist with each jail's own effective
// ignoreip. The generated file is temporarily removed so its earlier entries
// are not mistaken for admin-managed native configuration.
func captureNativeIgnoreip(f2bPolicy string, allow []string) (map[string][]string, error) {
	original, err := os.ReadFile(f2bPolicy)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("无法暂存 %s；未更改任何策略：%w", f2bPolicy, err)
	}
	moved := err == nil
	restore := func() error {
		if !moved {
			return nil
		}
		if err := writeFileAtomic(f2bPolicy, original, 0644); err != nil {
			return fmt.Errorf("无法恢复 %s：%w", f2bPolicy, err)
		}
		moved = false
		return nil
	}
	defer restore()

	if moved {
		if err := os.Remove(f2bPolicy); err != nil {
			return nil, fmt.Errorf("无法暂存 %s；未更改任何策略：%w", f2bPolicy, err)
		}
	}
	dump, dumpErr := exec.Command("fail2ban-client", "-d").Output()
	if dumpErr != nil || len(bytes.TrimSpace(dump)) == 0 {
		if rerr := restore(); rerr != nil {
			logf("policy-apply: 警告：%v", rerr)
		}
		return nil, errors.New("无法读取 fail2ban 当前配置；未更改任何策略。")
	}
	if err := restore(); err != nil {
		return nil, err
	}

	return mergeNativeIgnoreip(dump, allow)
}

// mergeNativeIgnoreip combines the whitelist with each driven jail's native
// addignoreip entries. The dump is a Python-repr-like list; strip its
// punctuation and parse strictly. Never execute or interpolate it.
func mergeNativeIgnoreip(dump []byte, allow []string) (map[string][]string, error) {
	merged := make(map[string][]string, len(policyJails))
	for _, jail := range policyJails {
		entries := make([]string, 0, len(allow))
		seen := make(map[string]struct{}, len(allow))
		for _, e := range allow {
			if _, ok := seen[e]; ok {
				continue
			}
			seen[e] = struct{}{}
			entries = append(entries, e)
		}
		merged[jail] = entries
	}

	for _, line := range strings.Split(string(dump), "\n") {
		if !strings.Contains(line, "addignoreip") {
			continue
		}
		s := strings.TrimPrefix(line, "[")
		s = strings.NewReplacer("[", "", "]", "", "'", "", `"`, "").Replace(s)
		fields := strings.Split(s, ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		if len(fields) < 4 || fields[0] != "set" || fields[2] != "addignoreip" {
			continue
		}
		jail := fields[1]
		entries, ok := merged[jail]
		if !ok {
			continue
		}
		seen := make(map[string]struct{}, len(entries))
		for _, e := range entries {
			seen[e] = struct{}{}
		}
		for _, token := range fields[3:] {
			if token == "" {
				continue
			}
			if !ignoreipToken.MatchString(token) {
				return nil, fmt.Errorf("%s 的原生 ignoreip 含非法条目；未更改任何策略。", jail)
			}
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			entries = append(entries, token)
		}
		merged[jail] = entries
	}
	return merged, nil
}

func restoreFail2banFile(path string, data []byte, had bool) {
	if had {
		if err := writeFileAtomic(path, data, 0644); err != nil {
			logf("policy-apply: 警告：无法恢复旧 ignoreip 文件 %s。", path)
		}
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logf("policy-apply: 警告：无法删除新 ignoreip 文件 %s。", path)
	}
}

// prepareFail2banFile reports whether the generated policy changed and the
// previous content needed for rollback. A missing jail.d keeps kernel policy
// only, matching the old applier.
func prepareFail2banFile(dir, path string, data []byte) (bool, []byte, bool, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		logf("policy-apply: 警告：未找到 %s；本次只应用内核策略，跳过 fail2ban ignoreip。", dir)
		return false, nil, false, nil
	}
	old, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil, false, nil
	}
	if err != nil {
		return false, nil, false, fmt.Errorf("无法备份 %s：%w", path, err)
	}
	return !bytes.Equal(old, data), old, true, nil
}

func clearWhitelistedBans(allow *Allowlist) {
	for _, jail := range policyJails {
		out, err := exec.Command("fail2ban-client", "status", jail).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			idx := strings.Index(line, "Banned IP list:")
			if idx < 0 {
				continue
			}
			for _, ip := range strings.Fields(line[idx+len("Banned IP list:"):]) {
				if !allow.Contains(ip) {
					continue
				}
				if err := exec.Command("fail2ban-client", "set", jail, "unbanip", ip).Run(); err != nil {
					logf("policy-apply: 警告：无法解除 %s 中已加白 IP %s 的封禁。", jail, ip)
				}
			}
		}
	}
}

func renderIntelNFT(intel, allow []string, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by caddy-abuseguard-policy at %s\n", now.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "add table inet %s\n", policyTable)
	fmt.Fprintf(&b, "delete table inet %s\n", policyTable)
	fmt.Fprintf(&b, "table inet %s {\n", policyTable)
	b.WriteString("\tset block4 {\n\t\ttype ipv4_addr\n")
	if len(intel) > 0 {
		b.WriteString("\t\telements = {\n")
		for i, e := range intel {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString("\t\t\t" + e)
		}
		b.WriteString("\n\t\t}\n")
	}
	b.WriteString("\t}\n\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n")
	// One rule per entry keeps overlapping IPs/CIDRs valid on every supported
	// nft version; each rule returns only from this dedicated chain.
	for _, e := range allow {
		if strings.Contains(e, ":") {
			fmt.Fprintf(&b, "\t\tip6 saddr %s return\n", e)
		} else {
			fmt.Fprintf(&b, "\t\tip saddr %s return\n", e)
		}
	}
	b.WriteString("\t\tip saddr @block4 drop\n\t}\n}\n")
	return []byte(b.String())
}

func renderAllowNFT(allow []string) []byte {
	var b strings.Builder
	b.WriteString("# Allowlist exceptions (one per line) at last apply; intel.nft is the applied snapshot.\n")
	for _, e := range allow {
		b.WriteString(e + "\n")
	}
	return []byte(b.String())
}

type policyAppliedMeta struct {
	AppliedAt        string `json:"applied_at"`
	IntelEntries     int    `json:"intel_entries"`
	WhitelistEntries int    `json:"whitelist_entries"`
	Source           string `json:"source"`
}

func renderApplied(now time.Time, intel, whitelist int) []byte {
	b, _ := json.Marshal(policyAppliedMeta{
		AppliedAt:        now.Format("2006-01-02T15:04:05Z"),
		IntelEntries:     intel,
		WhitelistEntries: whitelist,
		Source:           policyAppliedSrc,
	})
	return append(b, '\n')
}

func renderFail2banPolicy(whitelistPath string, byJail map[string][]string) []byte {
	var b strings.Builder
	b.WriteString("# Generated by caddy-abuseguard-policy. Do not edit.\n")
	fmt.Fprintf(&b, "# Source: %s + each jail's own native ignoreip. Apply: sudo ag --policy-apply\n", whitelistPath)
	for _, jail := range policyJails {
		entries := byJail[jail]
		if len(entries) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n[%s]\n", jail)
		for i, e := range entries {
			if i == 0 {
				fmt.Fprintf(&b, "ignoreip = %s\n", e)
			} else {
				fmt.Fprintf(&b, "           %s\n", e)
			}
		}
	}
	// Retired intel jails must not survive as live aliases, even if a copy of
	// the old definitions was left in jail.local by the operator.
	b.WriteString("\n[caddy-intel]\nenabled = false\n\n[sshd-intel]\nenabled = false\n")
	return []byte(b.String())
}

func nonEmptyLines(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// policyHasElements reports whether a previously applied policy had feed
// entries, from the root snapshot or the live set.
func policyHasElements(p policyPaths) bool {
	if data, err := os.ReadFile(p.intelNFT); err == nil && snapshotHasElements(data) {
		return true
	}
	out, err := exec.Command("nft", "-n", "list", "set", "inet", policyTable, "block4").Output()
	return err == nil && ipv4Element.Match(out)
}

func snapshotHasElements(data []byte) bool {
	return bytes.Contains(data, []byte("elements = {"))
}

func nftTableExists() bool {
	return exec.Command("nft", "list", "table", "inet", policyTable).Run() == nil
}

func restorePolicySnapshot(path string) {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	if err := nftCheckFile(path); err != nil {
		return
	}
	_ = nftApplyFile(path)
}

// captureLivePolicy dumps the live table so rollback restores what is actually
// enforced even if the disk snapshot is stale. The dump is wrapped in the same
// add/delete/table idiom as the main transaction so rollback is one atomic nft
// load instead of a delete-then-load gap.
func captureLivePolicy(work string) (bool, error) {
	if !nftTableExists() {
		return false, nil
	}
	out, err := exec.Command("nft", "list", "table", "inet", policyTable).Output()
	if err != nil {
		return false, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return false, errors.New("nft 返回空的内核策略")
	}
	if err := os.WriteFile(filepath.Join(work, "live.nft"), renderLivePolicy(out), 0600); err != nil {
		return false, err
	}
	return true, nil
}

// renderLivePolicy wraps a kernel dump in the add/delete/table idiom so a
// rollback is a single atomic nft load, never a delete-then-load gap.
func renderLivePolicy(dump []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "add table inet %s\n", policyTable)
	fmt.Fprintf(&b, "delete table inet %s\n", policyTable)
	b.Write(dump)
	return b.Bytes()
}

func backupPolicyFiles(p policyPaths) (policyDiskBackup, error) {
	var b policyDiskBackup
	var err error
	if b.intel, b.hadIntel, err = readBackup(p.intelNFT); err != nil {
		return b, err
	}
	if b.allow, b.hadAllow, err = readBackup(p.allowNFT); err != nil {
		return b, err
	}
	if b.applied, b.hadApp, err = readBackup(p.applied); err != nil {
		return b, err
	}
	return b, nil
}

func readBackup(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// rollbackPolicy restores the live kernel policy first, then the disk
// snapshots. Rollback errors are logged, never suppressed.
func rollbackPolicy(p policyPaths, work string, hadLive bool, b policyDiskBackup) {
	if hadLive {
		livePath := filepath.Join(work, "live.nft")
		if err := nftApplyFile(livePath); err != nil {
			logf("policy-apply: 警告：无法恢复上一次内核情报策略，请检查 nft list table inet %s：%v", policyTable, err)
		}
	} else if nftTableExists() {
		if err := exec.Command("nft", "delete", "table", "inet", policyTable).Run(); err != nil {
			logf("policy-apply: 警告：无法删除新建的情报表 inet %s：%v", policyTable, err)
		}
	}
	restoreDiskFile(p.intelNFT, b.intel, b.hadIntel)
	restoreDiskFile(p.allowNFT, b.allow, b.hadAllow)
	restoreDiskFile(p.applied, b.applied, b.hadApp)
}

func restoreDiskFile(path string, data []byte, had bool) {
	if had {
		if err := writeFileAtomic(path, data, 0640); err != nil {
			logf("policy-apply: 警告：无法恢复 %s：%v", path, err)
		}
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		logf("policy-apply: 警告：无法删除 %s：%v", path, err)
	}
}

func nftCheckFile(path string) error {
	cmd := exec.Command("nft", "-c", "-f", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func nftApplyFile(path string) error {
	cmd := exec.Command("nft", "-f", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
