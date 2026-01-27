# Go WHOIS Lookup Package
[![Go version](https://img.shields.io/github/go-mod/go-version/tiger586/whois)](https://github.com/tiger586/whois/blob/main/go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/tiger586/whois)](https://goreportcard.com/report/github.com/tiger586/whois)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/tiger586/whois?status.svg)](https://godoc.org/github.com/tiger586/whois)

- 一個功能完整、並發安全的 Go WHOIS 查詢套件，支援自動發現 WHOIS 伺服器、解析域名到期日，以及多種日期格式。  
- 通用的關鍵字查詢函數，方便擴充查詢內容。

## ✨ 特色功能

- 🔍 **自動發現 WHOIS 伺服器** - 透過 IANA 自動查找正確的 WHOIS 伺服器
- 💾 **智能快取機制** - 自動快取已知的 WHOIS 伺服器，提升查詢效率
- 🔒 **並發安全** - 使用 `sync.RWMutex` 和 `sync.Once` 確保執行緒安全
- 📅 **多格式日期解析** - 支援 ISO8601、TWNIC (UTC+8)、以及 10+ 種日期格式
- ✅ **域名驗證** - 內建 RFC 標準的域名格式驗證
- ⚡ **效能優化** - 非同步快取儲存、可配置超時時間、限制回應大小
- 🛠️ **實用工具** - 提供到期檢查、剩餘天數計算等輔助函數
- 📊 **結構化結果** - 返回包含完整資訊的結構化資料

## 📦 安裝

```bash
go get -u github.com/tiger586/whois
```

## 🚀 快速開始

### 基本查詢

```go
package main

import (
    "fmt"
    "log"
    "github.com/tiger586/whois"
)

func main() {
    result, err := whois.Lookup("example.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("域名: %s\n", result.Domain)
    fmt.Printf("WHOIS 伺服器: %s\n", result.Server)
    fmt.Printf("到期日: %s\n", result.Expiry.Format("2006-01-02"))
    fmt.Printf("查詢時間: %s\n", result.QueryTime)
}
```

### 檢查 WHOIS 回應是否表示域名不存在

```go
result, err := whois.Lookup("this-domain-definitely-does-not-exist-12345.com")
if err != nil {
    log.Fatal(err)
}

if !result.Found {
    fmt.Println("❌ 域名未註冊或不存在")
} else {
    fmt.Println("✅ 域名已註冊")
    if !result.Expiry.IsZero() {
        fmt.Printf("到期日: %s\n", result.Expiry.Format("2006-01-02"))
    }
}
```

### 檢查域名到期狀態

```go
result, err := whois.Lookup("example.com")
if err != nil {
    log.Fatal(err)
}

if whois.IsExpired(result.Expiry) {
    fmt.Println("❌ 域名已過期")
} else if whois.IsExpiringSoon(result.Expiry, 30) {
    days := whois.DaysUntilExpiry(result.Expiry)
    fmt.Printf("⚠️  域名將在 %d 天後到期\n", days)
} else {
    days := whois.DaysUntilExpiry(result.Expiry)
    fmt.Printf("✅ 域名還有 %d 天到期\n", days)
}
```

### 並發查詢多個域名

```go
package main

import (
    "fmt"
    "sync"
    "github.com/tiger586/whois"
)

func main() {
    domains := []string{"example.com", "google.com", "github.com"}
    
    var wg sync.WaitGroup
    results := make(chan *whois.LookupResult, len(domains))
    
    for _, domain := range domains {
        wg.Add(1)
        go func(d string) {
            defer wg.Done()
            if result, err := whois.Lookup(d); err == nil {
                results <- result
            }
        }(domain)
    }
    
    go func() {
        wg.Wait()
        close(results)
    }()
    
    for result := range results {
        fmt.Printf("%s 到期: %s\n", 
            result.Domain, 
            result.Expiry.Format("2006-01-02"))
    }
}
```

## 📖 API 文件

### 主要函數

#### `Lookup(domain string) (*LookupResult, error)`

執行 WHOIS 查詢並返回完整結果

```go
result, err := whois.Lookup("example.com")
if err != nil {
    log.Fatal(err)
}

fmt.Println(result.Domain)      // "example.com"
fmt.Println(result.Server)      // "whois.verisign-grs.com"
fmt.Println(result.Expiry)      // 2025-08-13 04:00:00 +0000 UTC
fmt.Println(result.QueryTime)   // 342ms
```

#### `GetWhoisServer(domain string) (string, error)`

取得域名對應的 WHOIS 伺服器

```go
server, err := whois.GetWhoisServer("example.com")
// server: "whois.verisign-grs.com"
```

#### `ValidateDomain(domain string) error`

驗證域名格式是否有效

```go
if err := whois.ValidateDomain("example.com"); err != nil {
    log.Fatal("無效的域名")
}
```

#### `ParseExpiry(whoisText string) (expiry string, rawLine string)`

從 WHOIS 回應中解析到期日

```go
expiry, raw := whois.ParseExpiry(result.RawResponse)
```

#### `ParseExpiryTime(expiryStr string) (*time.Time, error)`

將到期日字串解析為 `time.Time`

**支援格式：**
- `2006-01-02T15:04:05Z` (ISO8601)
- `2006-01-02 15:04:05 (UTC+8)` (TWNIC)
- `2006-01-02 15:04:05`
- `2006/01/02 15:04:05`
- `2006.01.02 15:04:05`
- `2006-01-02`
- `02-Jan-2006`
- 更多...

### 輔助函數

#### `DaysUntilExpiry(expiry time.Time) int`

計算距離到期還有幾天

```go
days := whois.DaysUntilExpiry(result.Expiry)
fmt.Printf("還有 %d 天到期\n", days)
```

#### `IsExpired(expiry time.Time) bool`

檢查域名是否已過期

```go
if whois.IsExpired(result.Expiry) {
    fmt.Println("域名已過期")
}
```

#### `IsExpiringSoon(expiry time.Time, days int) bool`

檢查域名是否即將到期

```go
if whois.IsExpiringSoon(result.Expiry, 30) {
    fmt.Println("域名將在 30 天內到期")
}
```

### ✨ 三個通用的關鍵字查詢函數

#### `ExtractField(whoisText, keyword string) string`

擷取單一欄位

```go
result, _ := whois.Lookup("example.com")

// 擷取 Registrar WHOIS Server
registrarServer := whois.ExtractField(result.RawResponse, "Registrar WHOIS Server:")
fmt.Println(registrarServer) // 輸出: whois.ionos.com

// 擷取 Registrar
registrar := whois.ExtractField(result.RawResponse, "Registrar:")
fmt.Println(registrar) // 輸出: IONOS SE

// 擷取 Creation Date
created := whois.ExtractField(result.RawResponse, "Creation Date:")
fmt.Println(created) // 輸出: 1995-08-14T04:00:00Z
```

#### `ExtractFields(whoisText string, keywords []string) map[string]string`

批次擷取多個欄位

```go
result, _ := whois.Lookup("example.com")

keywords := []string{
    "Registrar:",
    "Registrar WHOIS Server:",
    "Creation Date:",
    "Registry Expiry Date:",
    "Updated Date:",
}

fields := whois.ExtractFields(result.RawResponse, keywords)

for keyword, value := range fields {
    fmt.Printf("%s %s\n", keyword, value)
}

// 輸出:
// Registrar: IONOS SE
// Registrar WHOIS Server: whois.ionos.com
// Creation Date: 1995-08-14T04:00:00Z
// Registry Expiry Date: 2025-08-13T04:00:00Z
```

#### `ExtractAllMatches(whoisText, keyword string) []string`

擷取所有符合的值

```go
result, _ := whois.Lookup("example.com")

// 擷取所有 Name Server
nameServers := whois.ExtractAllMatches(result.RawResponse, "Name Server:")
for _, ns := range nameServers {
    fmt.Println(ns)
}

// 輸出:
// A.IANA-SERVERS.NET
// B.IANA-SERVERS.NET
```

#### 📝 「通用的關鍵字查詢」完整使用範例

```go
package main

import (
    "fmt"
    "log"
    "github.com/tiger586/whois"
)

func main() {
    result, err := whois.Lookup("example.com")
    if err != nil {
        log.Fatal(err)
    }

    if !result.Found {
        fmt.Println("域名不存在")
        return
    }

    // 方法 1: 單一欄位查詢
    registrar := whois.ExtractField(result.RawResponse, "Registrar:")
    fmt.Printf("註冊商: %s\n", registrar)

    // 方法 2: 批次查詢
    fields := whois.ExtractFields(result.RawResponse, []string{
        "Registrar:",
        "Registrar WHOIS Server:",
        "Creation Date:",
        "Updated Date:",
    })

    for key, value := range fields {
        fmt.Printf("%s %s\n", key, value)
    }

    // 方法 3: 查詢多筆資料
    nameServers := whois.ExtractAllMatches(result.RawResponse, "Name Server:")
    fmt.Println("\nName Servers:")
    for _, ns := range nameServers {
        fmt.Printf("  - %s\n", ns)
    }

    // 原本的到期日功能仍然可用
    if !result.Expiry.IsZero() {
        fmt.Printf("\n到期日: %s\n", result.Expiry.Format("2006-01-02"))
        fmt.Printf("剩餘天數: %d\n", whois.DaysUntilExpiry(result.Expiry))
    }
}
```

### 資料結構

#### `LookupResult`

```go
type LookupResult struct {
    Domain      string        // 查詢的域名
    Server      string        // 使用的 WHOIS 伺服器
    RawResponse string        // WHOIS 原始回應
    Expiry      time.Time     // 到期時間
    ExpiryRaw   string        // 到期日原始字串
    QueryTime   time.Duration // 查詢耗時
	Found       bool          // 域名是否存在
}
```

## ⚙️ 配置

### 自訂快取檔案路徑

預設快取檔案為 `./whois_servers.json`，可以透過 `SetCachePath()` 自訂：

```go
whois.SetCachePath("/var/cache/whois/servers.json")
```

**注意：** 必須在第一次呼叫 `Lookup()` 之前設定。

## 🌍 支援的 TLD

透過 IANA 自動發現機制，理論上支援所有有效的頂級域名：

- ✅ 通用頂級域名 (gTLD): `.com`, `.net`, `.org`
- ✅ 國家代碼頂級域名 (ccTLD): `.tw`, `.cn`, `.jp`, `.uk`, `.us`
- ✅ 新頂級域名: `.io`, `.ai`

## 📝 使用範例

### 域名監控工具

```go
package main

import (
    "fmt"
    "log"
    "time"
    "github.com/tiger586/whois"
)

func main() {
    domains := []string{
        "example.com",
        "mycompany.com",
        "important-domain.tw",
    }

    fmt.Println("🔍 域名到期檢查\n")

    for _, domain := range domains {
        result, err := whois.Lookup(domain)
        if err != nil {
            log.Printf("❌ %s: %v\n", domain, err)
            continue
        }

        if result.Expiry.IsZero() {
            fmt.Printf("⚠️  %s: 無法取得到期日\n", domain)
            continue
        }

        days := whois.DaysUntilExpiry(result.Expiry)

        switch {
        case whois.IsExpired(result.Expiry):
            fmt.Printf("🔴 %s: 已過期 (%s)\n", 
                domain, result.Expiry.Format("2006-01-02"))
        case whois.IsExpiringSoon(result.Expiry, 30):
            fmt.Printf("🟡 %s: %d 天後到期\n", domain, days)
        default:
            fmt.Printf("✅ %s: %d 天後到期\n", domain, days)
        }

        time.Sleep(1 * time.Second) // 避免頻繁查詢
    }
}
```

### HTTP API 服務

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"
    "github.com/tiger586/whois"
)

type Response struct {
    Success bool                `json:"success"`
    Data    *whois.LookupResult `json:"data,omitempty"`
    Error   string              `json:"error,omitempty"`
}

func whoisHandler(w http.ResponseWriter, r *http.Request) {
    domain := r.URL.Query().Get("domain")
    if domain == "" {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(Response{
            Success: false,
            Error:   "domain parameter is required",
        })
        return
    }

    result, err := whois.Lookup(domain)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(Response{
            Success: false,
            Error:   err.Error(),
        })
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(Response{
        Success: true,
        Data:    result,
    })
}

func main() {
    http.HandleFunc("/whois", whoisHandler)
    log.Println("🚀 Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

使用：
```bash
curl "http://localhost:8080/whois?domain=example.com"
```

## 🔧 故障排除

### 快取檔案權限錯誤

```go
// 使用有寫入權限的目錄
whois.SetCachePath("/tmp/whois_servers.json")
```

### 無法解析到期日

某些 WHOIS 伺服器使用特殊格式：

```go
// 檢查原始回應
result, _ := whois.Lookup("example.com")
fmt.Println(result.RawResponse)

// 手動解析
expiry, raw := whois.ParseExpiry(result.RawResponse)
fmt.Printf("原始行: %s\n", raw)
```
