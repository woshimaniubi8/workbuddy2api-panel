package scheduler

import (
	"log"
	"sync"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
)

// enterpriseSwitchWarned 已提示过「企业切换会话」的 uid（进程内去重）。
//
// 该提示只是告知性文案（凭证可能被上游静默丢行为事件），**不是门控**：
// token_source=enterprise_switch 在个人身份登录的凭证上同样会出现（用户实测
// 反馈），据此跳过会让正常账号的成长任务永远不执行。按调度轮次重复打印会刷屏，
// 故每个账号每个进程只打一次。
var enterpriseSwitchWarned sync.Map

// warnEnterpriseSwitch 打印企业切换会话提示（每账号一次），不改变调用方的执行流程。
func warnEnterpriseSwitch(scope string, a *auth.Auth) {
	if a == nil {
		return
	}
	notice := a.EnterpriseSwitchNotice()
	if notice == "" {
		return
	}
	if _, loaded := enterpriseSwitchWarned.LoadOrStore(a.UID, struct{}{}); loaded {
		return
	}
	log.Printf("%s %s: WARN %s", scope, logfmt.Label(a.UID, a.Nickname), notice)
}
