package dialog

import (
	stdcontext "context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/silenceper/wechat/v2/aispeech/config"
	aispeechContext "github.com/silenceper/wechat/v2/aispeech/context"
	"github.com/silenceper/wechat/v2/aispeech/encryptor"
	"github.com/silenceper/wechat/v2/cache"
)

const testAESKey = "q1Os1ZMe0nG28KUEx9lg3HjK7V5QyXvi212fzsgDqgz"

type emptyAccessTokenHandle struct{}

func (emptyAccessTokenHandle) GetAccessToken() (string, error) {
	return "", nil
}

func (emptyAccessTokenHandle) GetAccessTokenContext(ctx stdcontext.Context) (string, error) {
	return "", nil
}

func TestAccessTokenCache(t *testing.T) {
	var tokenRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		body := readBody(t, r)
		assertSign(t, r, "token", body)
		if r.Header.Get("X-APPID") != "appid" {
			t.Fatalf("bad X-APPID: %s", r.Header.Get("X-APPID"))
		}
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"rid","data":{"access_token":"access-token"}}`))
	}))
	defer srv.Close()

	ak := NewAccessToken(&config.Config{
		AppID:   "appid",
		Token:   "token",
		Account: "admin",
		BaseURL: srv.URL,
		Cache:   cache.NewMemory(),
	})

	token, err := ak.GetAccessToken()
	if err != nil {
		t.Fatalf("GetAccessToken error: %v", err)
	}
	if token != "access-token" {
		t.Fatalf("bad token: %s", token)
	}
	token, err = ak.GetAccessToken()
	if err != nil {
		t.Fatalf("GetAccessToken second error: %v", err)
	}
	if token != "access-token" {
		t.Fatalf("bad token second: %s", token)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests)
	}
}

func TestAccessTokenCacheByAccount(t *testing.T) {
	var tokenRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests++
		body := readBody(t, r)
		assertSign(t, r, "token", body)

		var req AccessTokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("bad token body: %v", err)
		}
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"rid","data":{"access_token":"` + req.Account + `-token"}}`))
	}))
	defer srv.Close()

	memory := cache.NewMemory()
	cfgA := &config.Config{
		AppID:   "appid",
		Token:   "token",
		Account: "admin-a",
		BaseURL: srv.URL,
		Cache:   memory,
	}
	cfgB := &config.Config{
		AppID:   "appid",
		Token:   "token",
		Account: "admin-b",
		BaseURL: srv.URL,
		Cache:   memory,
	}

	tokenA, err := NewAccessToken(cfgA).GetAccessToken()
	if err != nil {
		t.Fatalf("GetAccessToken A error: %v", err)
	}
	tokenB, err := NewAccessToken(cfgB).GetAccessToken()
	if err != nil {
		t.Fatalf("GetAccessToken B error: %v", err)
	}
	if tokenA != "admin-a-token" || tokenB != "admin-b-token" {
		t.Fatalf("bad tokens: %s %s", tokenA, tokenB)
	}
	if tokenRequests != 2 {
		t.Fatalf("token requests = %d, want 2", tokenRequests)
	}
}

func TestAccessTokenEmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"rid","data":{"access_token":""}}`))
	}))
	defer srv.Close()

	ak := NewAccessToken(&config.Config{
		AppID:   "appid",
		Token:   "token",
		BaseURL: srv.URL,
		Cache:   cache.NewMemory(),
	})

	if _, err := ak.GetAccessToken(); err == nil {
		t.Fatal("GetAccessToken should return error")
	}
}

func TestDialogAPIs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readBody(t, r)
		assertSign(t, r, "token", body)
		switch r.URL.Path {
		case "/v2/token":
			if r.Header.Get("X-APPID") != "appid" {
				t.Fatalf("bad X-APPID: %s", r.Header.Get("X-APPID"))
			}
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"token-rid","data":{"access_token":"access-token"}}`))
		case "/v2/bot/import/json":
			assertToken(t, r)
			var req ImportJSONRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("bad import body: %v", err)
			}
			if len(req.Data) != 1 || req.Data[0].Skill != "售前咨询" {
				t.Fatalf("bad import request: %+v", req)
			}
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"import-rid","data":{"task_id":"task-import"}}`))
		case "/v2/bot/publish":
			assertToken(t, r)
			if len(body) != 0 {
				t.Fatalf("publish body should be empty: %s", body)
			}
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"publish-rid","data":{"task_id":"task-publish"}}`))
		case "/v2/bot/effective_progress":
			assertToken(t, r)
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"progress-rid","data":{"end_time":"","progress":100,"status":1}}`))
		case "/v2/async/fetch":
			assertToken(t, r)
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"fetch-rid","data":{"state":2,"msg":"","progress":100,"start":1,"end":2,"url":"","success_skill_info":[{"id":1,"name":"AAA","intents":[{"id":2,"name":"BBB"}]}]}}`))
		case "/v2/bot/query":
			assertToken(t, r)
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
				t.Fatalf("bad content type: %s", r.Header.Get("Content-Type"))
			}
			plain, err := encryptor.Decrypt(testAESKey, string(body))
			if err != nil {
				t.Fatalf("decrypt query body error: %v", err)
			}
			var req QueryRequest
			if err = json.Unmarshal(plain, &req); err != nil {
				t.Fatalf("bad query body: %v", err)
			}
			if req.Query != "你好" {
				t.Fatalf("bad query: %+v", req)
			}
			cipherText, err := encryptor.Encrypt(testAESKey, []byte(`{"code":0,"msg":"success","request_id":"query-rid","data":{"answer":"你好呀","answer_type":"text","skill_name":"skill","intent_name":"intent","msg_id":"msg","status":"FAQ","slots":[{"name":"n","value":"v","norm":"v"}]}}`))
			if err != nil {
				t.Fatalf("encrypt response error: %v", err)
			}
			_, _ = w.Write([]byte(cipherText))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		AppID:   "appid",
		Token:   "token",
		AESKey:  testAESKey,
		Account: "admin",
		BaseURL: srv.URL,
		Cache:   cache.NewMemory(),
	}
	d := NewDialog(&aispeechContext.Context{
		Config:                   cfg,
		AccessTokenContextHandle: NewAccessToken(cfg),
	})

	importRes, err := d.ImportJSON(&ImportJSONRequest{
		Mode: 0,
		Data: []BotIntent{{
			Skill:     "售前咨询",
			Intent:    "查询营业时间",
			Disable:   false,
			Questions: []string{"你们几点开门"},
			Answers:   []string{"9:00-18:00"},
		}},
	})
	if err != nil || importRes.TaskID != "task-import" || importRes.RequestID != "import-rid" {
		t.Fatalf("ImportJSON = %+v, %v", importRes, err)
	}

	publishRes, err := d.Publish()
	if err != nil || publishRes.TaskID != "task-publish" {
		t.Fatalf("Publish = %+v, %v", publishRes, err)
	}

	progressRes, err := d.GetEffectiveProgress(&EffectiveProgressRequest{Env: "online"})
	if err != nil || progressRes.Progress != 100 {
		t.Fatalf("GetEffectiveProgress = %+v, %v", progressRes, err)
	}

	fetchRes, err := d.FetchAsync(&FetchAsyncRequest{TaskID: "task-import"})
	if err != nil || fetchRes.State != 2 || len(fetchRes.SuccessSkillInfo) != 1 {
		t.Fatalf("FetchAsync = %+v, %v", fetchRes, err)
	}

	queryRes, err := d.Query(&QueryRequest{Query: "你好", Env: "online"})
	if err != nil || queryRes.Answer != "你好呀" || queryRes.RequestID != "query-rid" {
		t.Fatalf("Query = %+v, %v", queryRes, err)
	}
}

func TestDialogEmptyAccessToken(t *testing.T) {
	d := NewDialog(&aispeechContext.Context{
		Config: &config.Config{
			AESKey: testAESKey,
		},
		AccessTokenContextHandle: emptyAccessTokenHandle{},
	})

	if _, err := d.ImportJSON(&ImportJSONRequest{}); err == nil {
		t.Fatal("ImportJSON should return error")
	}
	if _, err := d.Publish(); err == nil {
		t.Fatal("Publish should return error")
	}
	if _, err := d.Query(&QueryRequest{}); err == nil {
		t.Fatal("Query should return error")
	}
}

func TestDialogAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/token":
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"token-rid","data":{"access_token":"access-token"}}`))
		case "/v2/bot/import/json":
			_, _ = w.Write([]byte(`{"code":210202,"msg":"权限不足","request_id":"import-rid","data":{"reason":"forbidden"}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		AppID:   "appid",
		Token:   "token",
		BaseURL: srv.URL,
		Cache:   cache.NewMemory(),
	}
	d := NewDialog(&aispeechContext.Context{
		Config:                   cfg,
		AccessTokenContextHandle: NewAccessToken(cfg),
	})

	_, err := d.ImportJSON(&ImportJSONRequest{})
	if err == nil {
		t.Fatal("ImportJSON should return error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("ImportJSON error should be *APIError but %T", err)
	}
	if apiErr.Code != 210202 || apiErr.Msg != "权限不足" || apiErr.RequestID != "import-rid" {
		t.Fatalf("bad api error: %+v", apiErr)
	}
	if string(apiErr.Data) != `{"reason":"forbidden"}` {
		t.Fatalf("bad api error data: %s", apiErr.Data)
	}
}

func TestQueryPlainJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/token":
			_, _ = w.Write([]byte(`{"code":0,"msg":"success","request_id":"token-rid","data":{"access_token":"access-token"}}`))
		case "/v2/bot/query":
			_, _ = w.Write([]byte(`{"code":110002,"msg":"参数错误","request_id":"query-rid"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		AppID:   "appid",
		Token:   "token",
		AESKey:  testAESKey,
		BaseURL: srv.URL,
		Cache:   cache.NewMemory(),
	}
	d := NewDialog(&aispeechContext.Context{
		Config:                   cfg,
		AccessTokenContextHandle: NewAccessToken(cfg),
	})

	_, err := d.Query(&QueryRequest{Query: "你好"})
	if err == nil {
		t.Fatal("Query should return error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("Query error should be *APIError but %T", err)
	}
	if apiErr.Code != 110002 || apiErr.RequestID != "query-rid" {
		t.Fatalf("bad api error: %+v", apiErr)
	}
}

func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body error: %v", err)
	}
	return body
}

func assertToken(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Header.Get("X-OPENAI-TOKEN") != "access-token" {
		t.Fatalf("bad X-OPENAI-TOKEN: %s", r.Header.Get("X-OPENAI-TOKEN"))
	}
}

func assertSign(t *testing.T, r *http.Request, token string, body []byte) {
	t.Helper()
	timestamp, err := strconv.ParseInt(r.Header.Get("timestamp"), 10, 64)
	if err != nil {
		t.Fatalf("bad timestamp: %v", err)
	}
	want := encryptor.Sign(token, timestamp, r.Header.Get("nonce"), body)
	if got := r.Header.Get("sign"); got != want {
		t.Fatalf("bad sign: got %s want %s body %s", got, want, body)
	}
}
