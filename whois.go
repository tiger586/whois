package whois

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =======================
// Generic Field Extraction
// =======================

// ExtractField 從 WHOIS 回應中擷取指定關鍵字的值
//
// 例如: ExtractField(whoisText, "Registrar WHOIS Server:")
//
// 返回: "whois.ionos.com"
func ExtractField(whoisText, keyword string) string {
	if whoisText == "" || keyword == "" {
		return ""
	}

	lines := strings.Split(whoisText, "\n")
	keyword = strings.TrimSpace(keyword)
	keywordLower := strings.ToLower(keyword)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lineLower := strings.ToLower(line)

		// 檢查是否包含關鍵字
		if strings.HasPrefix(lineLower, keywordLower) {
			// 移除關鍵字部分，取得值
			value := line[len(keyword):]
			value = strings.TrimSpace(value)
			return value
		}
	}

	return ""
}

// ExtractFields 從 WHOIS 回應中擷取多個關鍵字的值
//
// 返回 map[keyword]value
func ExtractFields(whoisText string, keywords []string) map[string]string {
	result := make(map[string]string)

	for _, keyword := range keywords {
		value := ExtractField(whoisText, keyword)
		if value != "" {
			result[keyword] = value
		}
	}

	return result
}

// ExtractAllMatches 擷取所有符合關鍵字的行（可能有多筆）
//
// 例如某些 WHOIS 回應中 Name Server 有多個
func ExtractAllMatches(whoisText, keyword string) []string {
	if whoisText == "" || keyword == "" {
		return nil
	}

	var matches []string
	lines := strings.Split(whoisText, "\n")
	keyword = strings.TrimSpace(keyword)
	keywordLower := strings.ToLower(keyword)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lineLower := strings.ToLower(line)

		if strings.HasPrefix(lineLower, keywordLower) {
			value := line[len(keyword):]
			value = strings.TrimSpace(value)
			if value != "" {
				matches = append(matches, value)
			}
		}
	}

	return matches
}

// =======================
// Domain Status Detection
// =======================

var notFoundKeywords = []string{
	"no match",
	"not found",
	"no data found",
	"no entries found",
	"domain not found",
	"no such domain",
	"status: available",
	"status: free",
	"not registered",
	"has not been registered",
	"domain name not known",
	"no matching record",
	"無符合資料",
	"查無資料",
}

// isDomainNotFound 檢查 WHOIS 回應是否表示域名不存在
func isDomainNotFound(whoisText string) bool {
	if whoisText == "" {
		return true
	}

	lower := strings.ToLower(whoisText)

	for _, keyword := range notFoundKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}

	return false
}

// =======================
// Configuration
// =======================

const (
	defaultWhoisPort   = "43"
	defaultTimeout     = 5 * time.Second
	defaultReadTimeout = 6 * time.Second
	defaultIANAServer  = "whois.iana.org"
	defaultServersFile = "./whois_servers.json"
	maxResponseSize    = 10 * 1024 * 1024 // 10MB
)

// =======================
// WHOIS Server Cache
// =======================

type ServerCache struct {
	servers map[string]string
	mu      sync.RWMutex
	once    sync.Once
	path    string
}

var globalCache = &ServerCache{
	servers: make(map[string]string),
	path:    defaultServersFile,
}

// SetCachePath 設置快取檔案路徑（需在首次使用前呼叫）
func SetCachePath(path string) {
	globalCache.path = path
}

// LoadCache 載入 WHOIS 伺服器快取
func (c *ServerCache) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			c.servers = make(map[string]string)
			return nil
		}
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	if err := json.Unmarshal(data, &c.servers); err != nil {
		return fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	return nil
}

// Save 儲存快取到檔案
func (c *ServerCache) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c.servers, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	if err := os.WriteFile(c.path, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// Get 取得快取的伺服器
func (c *ServerCache) Get(tld string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	server, ok := c.servers[tld]
	return server, ok
}

// Set 設置快取
func (c *ServerCache) Set(tld, server string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.servers[tld] = server
}

// ensureLoaded 確保快取已載入（只執行一次）
func (c *ServerCache) ensureLoaded() {
	c.once.Do(func() {
		_ = c.Load()
	})
}

// =======================
// Expiry Keywords & Patterns
// =======================

var expiryKeywords = []string{
	"expiry",
	"expiration",
	"expires",
	"paid-till",
	"registry expiry date",
	"registrar registration expiration date",
	"[有効期限]",
}

var datePatterns = []string{
	"2006-01-02T15:04:05Z",      // ISO8601
	"2006-01-02T15:04:05Z07:00", // ISO8601 with timezone
	"2006-01-02 15:04:05",       // Date time
	"2006/01/02 15:04:05",       // Date time with /
	"2006.01.02 15:04:05",       // Date time with .
	"2006-01-02",                // Date only
	"2006/01/02",                // Date only with /
	"2006.01.02",                // Date only with .
	"02-Jan-2006",               // DD-Mon-YYYY
	"02/01/2006 15:04:05",       // DD/MM/YYYY HH:MM:SS
	"Jan 02 2006",               // Mon DD YYYY
}

var dateRegexes = []*regexp.Regexp{
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}`),
	regexp.MustCompile(`\d{4}/\d{2}/\d{2}`),
	regexp.MustCompile(`\d{4}\.\d{2}\.\d{2}`),
	regexp.MustCompile(`\d{2}-[A-Za-z]{3}-\d{4}`),
	regexp.MustCompile(`\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}`),
	regexp.MustCompile(`[A-Za-z]{3} \d{2} \d{4}`),
}

// TWNIC 特殊格式: 2032-11-02 16:44:32 (UTC+8)
var twnicRegex = regexp.MustCompile(`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \(UTC([+-]\d+)\)`)

// =======================
// Domain Validation
// =======================

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// ValidateDomain 驗證域名格式
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain too long (max 253 characters)")
	}

	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	return nil
}

// =======================
// Utilities
// =======================

// GetTLD 提取頂級域名
func GetTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

// =======================
// WHOIS Server Discovery
// =======================

// GetWhoisServer 取得域名對應的 WHOIS 伺服器
func GetWhoisServer(domain string) (string, error) {
	if err := ValidateDomain(domain); err != nil {
		return "", err
	}

	globalCache.ensureLoaded()
	tld := GetTLD(domain)

	// 檢查快取
	if server, ok := globalCache.Get(tld); ok {
		return server, nil
	}

	// 查詢 IANA
	server, err := queryIANA(tld)
	if err != nil {
		// Fallback to IANA server
		return defaultIANAServer, fmt.Errorf("failed to query IANA for %s: %w", tld, err)
	}

	// 更新快取
	globalCache.Set(tld, server)

	// 非同步儲存（不阻塞主流程）
	go func() {
		if err := globalCache.Save(); err != nil {
			// 可以加入 logging
			_ = err
		}
	}()

	return server, nil
}

// queryIANA 向 IANA 查詢 TLD 的 WHOIS 伺服器
func queryIANA(tld string) (string, error) {
	conn, err := net.DialTimeout("tcp", defaultIANAServer+":"+defaultWhoisPort, defaultTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to IANA: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
		return "", fmt.Errorf("failed to set deadline: %w", err)
	}

	// 傳送 TLD 查詢
	if _, err := fmt.Fprintf(conn, "%s\r\n", tld); err != nil {
		return "", fmt.Errorf("failed to send query: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), maxResponseSize)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "whois:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanner error: %w", err)
	}

	return "", fmt.Errorf("no whois server found for TLD: %s", tld)
}

// =======================
// WHOIS Lookup
// =======================

// LookupResult WHOIS 查詢結果
type LookupResult struct {
	Domain      string        // 查詢的域名
	Server      string        // 使用的 WHOIS 伺服器
	RawResponse string        // WHOIS 原始回應
	Expiry      time.Time     // 到期時間
	ExpiryRaw   string        // 到期日原始字串
	QueryTime   time.Duration // 查詢耗時
	Found       bool          // 域名是否存在
}

// Lookup 執行 WHOIS 查詢
func Lookup(domain string) (*LookupResult, error) {
	startTime := time.Now()

	if err := ValidateDomain(domain); err != nil {
		return nil, err
	}

	server, err := GetWhoisServer(domain)
	if err != nil {
		return nil, err
	}

	rawResponse, err := queryWhois(server, domain)
	if err != nil {
		return nil, err
	}

	result := &LookupResult{
		Domain:      domain,
		Server:      server,
		RawResponse: rawResponse,
		QueryTime:   time.Since(startTime),
		Found:       !isDomainNotFound(rawResponse),
	}

	// 解析到期日
	if expiryStr, raw := ParseExpiry(rawResponse); expiryStr != "" {
		if expiry, err := ParseExpiryTime(expiryStr); err == nil {
			result.Expiry = *expiry
			result.ExpiryRaw = raw
		}
	}

	return result, nil
}

// queryWhois 執行實際的 WHOIS 查詢
func queryWhois(server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":"+defaultWhoisPort, defaultTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", server, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(defaultReadTimeout)); err != nil {
		return "", fmt.Errorf("failed to set deadline: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "%s\r\n", domain); err != nil {
		return "", fmt.Errorf("failed to send query: %w", err)
	}

	var result strings.Builder
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), maxResponseSize)

	for scanner.Scan() {
		result.WriteString(scanner.Text())
		result.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanner error: %w", err)
	}

	return result.String(), nil
}

// =======================
// Expiry Parser
// =======================

// ExpiryInfo 到期日資訊
type ExpiryInfo struct {
	Found   bool
	Expiry  string
	RawLine string
}

// ParseExpiry 從 WHOIS 回應中解析到期日
func ParseExpiry(whoisText string) (expiry string, rawLine string) {
	if whoisText == "" {
		return "", ""
	}

	lines := strings.Split(whoisText, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)

		// 檢查是否包含到期關鍵字
		for _, keyword := range expiryKeywords {
			if strings.Contains(lower, keyword) {
				// 嘗試從整行抽取日期
				for _, re := range dateRegexes {
					if match := re.FindString(line); match != "" {
						return strings.TrimSpace(match), line
					}
				}
				// 找到關鍵字但沒抓到日期，仍保留原始行
				return "", line
			}
		}
	}

	return "", ""
}

// ParseExpiryTime 將到期日字串解析為 time.Time
func ParseExpiryTime(expiryStr string) (*time.Time, error) {
	if expiryStr == "" {
		return nil, fmt.Errorf("empty expiry string")
	}

	expiryStr = strings.TrimSpace(expiryStr)

	// 1. 處理 TWNIC 特殊格式: 2032-11-02 16:44:32 (UTC+8)
	if m := twnicRegex.FindStringSubmatch(expiryStr); len(m) == 3 {
		dateTime := m[1]
		offset := m[2]

		hourOffset, err := parseOffset(offset)
		if err != nil {
			return nil, fmt.Errorf("invalid timezone offset: %w", err)
		}

		loc := time.FixedZone("UTC"+offset, hourOffset*3600)
		t, err := time.ParseInLocation("2006-01-02 15:04:05", dateTime, loc)
		if err != nil {
			return nil, fmt.Errorf("failed to parse TWNIC format: %w", err)
		}
		return &t, nil
	}

	// 2. 嘗試所有日期格式
	for _, pattern := range datePatterns {
		if t, err := time.Parse(pattern, expiryStr); err == nil {
			return &t, nil
		}
	}

	return nil, fmt.Errorf("unsupported expiry format: %s", expiryStr)
}

// parseOffset 解析時區偏移量
func parseOffset(offset string) (int, error) {
	sign := 1
	s := offset

	if strings.HasPrefix(s, "-") {
		sign = -1
		s = strings.TrimPrefix(s, "-")
	} else {
		s = strings.TrimPrefix(s, "+")
	}

	hours, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid offset value: %w", err)
	}

	return sign * hours, nil
}

// =======================
// Helper Functions
// =======================

// DaysUntilExpiry 計算距離到期還有幾天
func DaysUntilExpiry(expiry time.Time) int {
	duration := time.Until(expiry)
	return int(duration.Hours() / 24)
}

// IsExpired 檢查域名是否已過期
func IsExpired(expiry time.Time) bool {
	return time.Now().After(expiry)
}

// IsExpiringSoon 檢查域名是否即將到期（預設 30 天內）
func IsExpiringSoon(expiry time.Time, days int) bool {
	if days <= 0 {
		days = 30
	}
	threshold := time.Now().AddDate(0, 0, days)
	return expiry.Before(threshold) && !IsExpired(expiry)
}
