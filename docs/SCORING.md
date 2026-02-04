# AgentShield 計分規則 v0.3.0

## 三維度架構

| 維度 | 權重 | 涵蓋 Scanner | 說明 |
|------|------|-------------|------|
| **Code Safety** | 40% | Secret Leak Scanner, Prompt Injection Tester, Skill Auditor | 直接攻擊面：密鑰洩漏、injection |
| **Config Safety** | 30% | MCP Config Auditor, Permission Analyzer, Channel Surface Auditor | 設定層：MCP、權限、通道 |
| **Defense Score** | 30% | Defense Analyzer, Red Team Simulator | 防禦層：防護機制、紅隊模擬 |

Agent Config Auditor → 依 finding 類型分配到對應維度（預設 codeSafety）

## 計分公式

### 每個維度的分數
```
dimensionScore = 100 - totalPenalty
```

### Penalty 計算（對數遞減）
```
penalty(count, base, max) = min(base × log₂(count + 1), max)
```

| 嚴重度 | Base Penalty | Max Cap |
|--------|-------------|---------|
| 🔴 Critical | 20 | 50 |
| 🟠 High | 5 | 30 |
| 🟡 Medium | 1.5 | 15 |
| 🔵 Info | 0 | 0 |

### Interaction Penalty
當 Critical 和 High 同時存在時，額外扣分：
```
interactionPenalty = min(5 × log₂(min(critical, high) + 1), 10)
```

### Confidence 加權
- `definite`: 1.0（完全計入）
- `likely`: 0.8
- `possible`: 0.6

### 總分計算
```
weightedScore = codeSafety × 0.4 + configSafety × 0.3 + defenseScore × 0.3
```

### 🔒 地板規則（Floor Rule）
**任何維度 < 60（F 等級）時，總分上限 = 該維度分數 + 10**

原理：安全是木桶效應，一個維度崩潰不應被其他維度救回。
- 密鑰洩漏（Code Safety F）→ 不管防禦多好都危險
- 設定全開（Config Safety F）→ 不管程式碼多安全都白搭

## 等級對照

| 分數 | 等級 |
|------|------|
| 97-100 | A+ |
| 93-96 | A |
| 90-92 | A- |
| 87-89 | B+ |
| 83-86 | B |
| 80-82 | B- |
| 77-79 | C+ |
| 73-76 | C |
| 70-72 | C- |
| 67-69 | D+ |
| 63-66 | D |
| 60-62 | D- |
| 0-59 | F |

## 標準測試場景

### 1. 預設安裝 + API key（無防護）→ 預期 D 等級
- 最小 config（127.0.0.1, 預設 port）
- 一個 channel，無 auth、無 allowFrom
- auth-profiles 有 API key
- 無 SOUL.md 防護、無 prompt hardening

### 2. 功能豐富 + 密鑰散落 + 無防護 → 預期 F 等級
- 多 channel（Telegram + Discord + Slack）全 open
- 無 gateway auth
- TOOLS.md 塞滿密碼（SSH、DB、Stripe、GitHub PAT、AWS）
- MCP server 內含密鑰
- memory/ 裡存 credentials
- SOUL.md 無任何安全條款

### 3. 功能豐富 + 完整防護 → 預期 B 等級
- gateway 有 token auth + 隨機 port
- channel 有 allowFrom + restricted dmPolicy
- 密鑰用環境變數（不明文）
- SOUL.md 有身份防護、指令優先級、拒絕條款
- AGENTS.md 有安全規範
- 有 logging + redactSensitive

## 設計原則

1. **對數遞減** — 第一個 Critical 扣最重，之後遞減，避免重複問題無限扣分
2. **嚴重度上限** — 每個等級有 max cap，單一類型不會獨佔所有扣分
3. **加權平均** — 三維度按重要性加權，Code Safety 佔最多（40%）
4. **地板規則** — F 維度直接壓總分，防止好維度救爛維度
5. **Confidence** — 不確定的 finding 扣分較少，減少 false positive 影響
6. **Context-aware** — test/doc 檔案自動降級、開發用密碼降級、.example 檔降級
