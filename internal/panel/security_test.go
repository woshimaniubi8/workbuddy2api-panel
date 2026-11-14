package panel

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func newTestPanel() *Panel {
	// 启用鉴权：未带 key 的请求一律 401，不进入依赖 Pool/Upstream 的 handler。
	return New(Config{Version: "test", APIKey: "test-key"})
}

// 面板安全响应头必须覆盖：页面、静态脚本、鉴权失败响应。
func TestSecurityHeadersOnAllPanelResponses(t *testing.T) {
	p := newTestPanel()
	paths := []struct{ method, path string }{
		{"GET", "/panel/"},
		{"GET", "/panel/app.js"},
		{"GET", "/panel/api/overview"}, // 401（未提供 key）
		{"POST", "/panel/api/config"},  // 401
		{"GET", "/panel/api/nonexistent"},
	}
	for _, c := range paths {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		h := rec.Header()
		if got := h.Get("Content-Security-Policy"); got == "" {
			t.Errorf("%s %s: missing CSP", c.method, c.path)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: X-Content-Type-Options=%q", c.method, c.path, h.Get("X-Content-Type-Options"))
		}
		if h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s %s: X-Frame-Options=%q", c.method, c.path, h.Get("X-Frame-Options"))
		}
		if h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s %s: Referrer-Policy=%q", c.method, c.path, h.Get("Referrer-Policy"))
		}
	}
}

// CSP 必须禁止内联脚本与 iframe 嵌套（严格策略的核心约束）。
func TestCSPDisallowsInlineScriptAndFraming(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/", nil))
	csp := rec.Header().Get("Content-Security-Policy")

	for _, must := range []string{
		"script-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"default-src 'none'",
	} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP missing %q; got: %s", must, csp)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("CSP must not allow unsafe-inline scripts; got: %s", csp)
	}
}

// 页面必须引用外部脚本（内联脚本会被上面的 CSP 拦掉，页面将完全不可用）。
func TestIndexReferencesExternalScript(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `<script src="app.js"></script>`) {
		t.Error("index.html must load app.js externally (inline script is blocked by CSP)")
	}
	// 反例保护：出现内联 <script>...</script> 内容块即为回归
	if strings.Contains(body, "<script>\n") || strings.Contains(body, "<script> ") {
		t.Error("index.html still contains an inline <script> block; CSP would block it")
	}
}

// index.html 不得含内联事件处理器（onsubmit/onclick/onkeydown…）：
// script-src 'self' 不含 unsafe-inline，内联处理器会被拦掉并在控制台刷
// "Executing inline event handler violates..." —— 处理器里的逻辑（例如
// onsubmit="return false" 挡表单提交）等于完全没生效。事件一律在 app.js 里绑定。
func TestIndexHTMLNoInlineEventHandlers(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/", nil))
	body := rec.Body.String()

	re := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	if m := re.FindString(body); m != "" {
		idx := strings.Index(body, m)
		start := idx - 80
		if start < 0 {
			start = 0
		}
		end := idx + 120
		if end > len(body) {
			end = len(body)
		}
		t.Fatalf("index.html contains inline event handler %q (blocked by CSP): ...%s...", m, body[start:end])
	}
}

// COOP 只对可信来源下发：浏览器会忽略 http://内网IP 上的 COOP 并打印
// "...origin was untrustworthy" 告警，面板常以 http://内网IP 部署，故需按来源判断。
func TestCOOPOnlyOnTrustworthyOrigin(t *testing.T) {
	p := newTestPanel()
	cases := []struct {
		name string
		req  func() *http.Request
		want bool
	}{
		{"http 内网 IP 不下发", func() *http.Request {
			return httptest.NewRequest("GET", "http://192.168.1.20:7863/panel/", nil)
		}, false},
		{"http 域名不下发", func() *http.Request {
			return httptest.NewRequest("GET", "http://panel.example.com/panel/", nil)
		}, false},
		{"localhost 下发", func() *http.Request {
			return httptest.NewRequest("GET", "http://localhost:7863/panel/", nil)
		}, true},
		{"127.0.0.1 下发", func() *http.Request {
			return httptest.NewRequest("GET", "http://127.0.0.1:7863/panel/", nil)
		}, true},
		{"https 下发", func() *http.Request {
			return httptest.NewRequest("GET", "https://panel.example.com/panel/", nil)
		}, true},
		{"反代 X-Forwarded-Proto=https 下发", func() *http.Request {
			req := httptest.NewRequest("GET", "http://panel.example.com/panel/", nil)
			req.Header.Set("X-Forwarded-Proto", "https")
			return req
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, c.req())
			got := rec.Header().Get("Cross-Origin-Opener-Policy")
			if c.want && got != "same-origin" {
				t.Errorf("COOP=%q want same-origin", got)
			}
			if !c.want && got != "" {
				t.Errorf("COOP=%q want empty (trustworthy-origin gated)", got)
			}
			// CORP 与来源可信性无关，任何来源都必须下发。
			if rec.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
				t.Error("CORP must always be set")
			}
		})
	}
}

// app.js 必须能作为同源脚本取到且类型正确（否则页面白屏）。
func TestAppScriptServed(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/app.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type=%q want javascript", ct)
	}
	if !strings.Contains(rec.Body.String(), "'use strict'") {
		t.Error("app.js body looks wrong")
	}
}

// UID 白名单：拒绝路径穿越与异常字符，放行真实 UUID 形态。
func TestValidUID(t *testing.T) {
	ok := []string{
		"248890d9-bb26-4131-87a7-4ec74d472344",
		"abc_123-XYZ",
		"a",
	}
	bad := []string{
		"",
		"../../evil",
		"x/../../y",
		`..\..\evil`,
		"a/b",
		"a\\b",
		"uid with space",
		"uid\nnewline",
		"uid\x00null",
		"café",
		strings.Repeat("a", 65), // 超长
	}
	for _, u := range ok {
		if !validUID(u) {
			t.Errorf("validUID(%q) = false, want true", u)
		}
	}
	for _, u := range bad {
		if validUID(u) {
			t.Errorf("validUID(%q) = true, want false", u)
		}
	}
}

// 未带密钥的 API 请求必须 401；携带正确密钥则通过鉴权层（不再是 401）。
func TestAuthLayerBehavior(t *testing.T) {
	p := newTestPanel()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", "/panel/api/overview", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: code=%d want 401", rec.Code)
	}
	// 用不存在的路由验证"带正确 key 已过鉴权"（避免触碰依赖 nil 的 handler）。
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/panel/api/nonexistent", nil)
	req2.Header.Set("Authorization", "Bearer test-key")
	p.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusUnauthorized {
		t.Error("valid key must pass the auth layer")
	}
}
