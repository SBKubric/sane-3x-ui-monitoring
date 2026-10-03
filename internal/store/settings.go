package store

import (
	"fmt"
	"strconv"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Settings keys (spec §9.4): the exact camelCase strings stored in the
// settings table's key column. Kept as named constants so a typo in a key
// name is a compile error in LoadSettings/SaveSettings rather than a setting
// that silently never round-trips.
const (
	settingPanelURL = "panelUrl"
	settingMonToken = "monToken"
	settingRealHost = "realHost"
	settingPanelCA  = "panelCa"

	settingTgToken  = "tgToken"
	settingTgChatID = "tgChatId"

	settingDownAfter          = "downAfter"
	settingUpAfter            = "upAfter"
	settingFlapN              = "flapN"
	settingFlapMin            = "flapMin"
	settingFlapHoldMin        = "flapHoldMin"
	settingClientOfflineAfter = "clientOfflineAfter"
	settingPanelDownAfter     = "panelDownAfter"

	settingIntervalMs         = "intervalMs"
	settingBudgetMs           = "budgetMs"
	settingConnectMs          = "connectMs"
	settingTlsMs              = "tlsMs"
	settingHeadersMs          = "headersMs"
	settingStartJitterMs      = "startJitterMs"
	settingHeartbeatTimeoutMs = "heartbeatTimeoutMs"
)

// Settings is the typed view of the settings table (spec §9.4): everything
// the admin UI's Settings page edits. Bootstrap config (internal/config)
// covers what a fresh install needs before this table even exists; once the
// database is up, every operational knob lives here instead, so changing a
// threshold or the panel URL never requires a restart.
type Settings struct {
	PanelURL, MonToken, RealHost string
	// PanelCA is a PEM chain (decision #52 §1): when set, requests to the
	// panel trust exactly these certificates instead of the system pool —
	// a stand panel on a self-signed certificate is trusted by pasting that
	// certificate here. Empty means the system pool.
	PanelCA           string
	TgToken, TgChatID string

	DownAfter, UpAfter, FlapN, FlapMin, FlapHoldMin, ClientOfflineAfter, PanelDownAfter int

	IntervalMs, BudgetMs, ConnectMs, TlsMs, HeadersMs, StartJitterMs, HeartbeatTimeoutMs int64
}

// DefaultSettings returns the spec's defaults (§9.4) for every threshold and
// probe parameter. PanelURL, MonToken, RealHost, PanelCA, TgToken and TgChatID have no
// sane default — an empty string there means "not configured yet", which the
// admin UI and the panel poll loop (step 3) both treat as "nothing to do".
func DefaultSettings() *Settings {
	return &Settings{
		DownAfter:          3,
		UpAfter:            2,
		FlapN:              4,
		FlapMin:            30,
		FlapHoldMin:        15,
		ClientOfflineAfter: 3,
		PanelDownAfter:     3,

		IntervalMs:         60000,
		BudgetMs:           30000,
		ConnectMs:          5000,
		TlsMs:              10000,
		HeadersMs:          10000,
		StartJitterMs:      5000,
		HeartbeatTimeoutMs: 10000,
	}
}

// LoadSettings reads the settings table into a Settings, filling in the
// spec's default for any key that has never been saved — a fresh install
// with an empty settings table gets DefaultSettings() back verbatim, and an
// install that has only ever changed one tab in the admin UI still gets
// correct defaults for every other tab.
func (s *Store) LoadSettings() (*Settings, error) {
	var rows []Setting
	if err := s.DB.Find(&rows).Error; err != nil {
		return nil, err
	}
	kv := make(map[string]string, len(rows))
	for _, r := range rows {
		kv[r.Key] = r.Value
	}

	out := DefaultSettings()
	out.PanelURL = strOr(kv, settingPanelURL, out.PanelURL)
	out.MonToken = strOr(kv, settingMonToken, out.MonToken)
	out.RealHost = strOr(kv, settingRealHost, out.RealHost)
	out.PanelCA = strOr(kv, settingPanelCA, out.PanelCA)
	out.TgToken = strOr(kv, settingTgToken, out.TgToken)
	out.TgChatID = strOr(kv, settingTgChatID, out.TgChatID)

	out.DownAfter = intOr(kv, settingDownAfter, out.DownAfter)
	out.UpAfter = intOr(kv, settingUpAfter, out.UpAfter)
	out.FlapN = intOr(kv, settingFlapN, out.FlapN)
	out.FlapMin = intOr(kv, settingFlapMin, out.FlapMin)
	out.FlapHoldMin = intOr(kv, settingFlapHoldMin, out.FlapHoldMin)
	out.ClientOfflineAfter = intOr(kv, settingClientOfflineAfter, out.ClientOfflineAfter)
	out.PanelDownAfter = intOr(kv, settingPanelDownAfter, out.PanelDownAfter)

	out.IntervalMs = int64Or(kv, settingIntervalMs, out.IntervalMs)
	out.BudgetMs = int64Or(kv, settingBudgetMs, out.BudgetMs)
	out.ConnectMs = int64Or(kv, settingConnectMs, out.ConnectMs)
	out.TlsMs = int64Or(kv, settingTlsMs, out.TlsMs)
	out.HeadersMs = int64Or(kv, settingHeadersMs, out.HeadersMs)
	out.StartJitterMs = int64Or(kv, settingStartJitterMs, out.StartJitterMs)
	out.HeartbeatTimeoutMs = int64Or(kv, settingHeartbeatTimeoutMs, out.HeartbeatTimeoutMs)

	return out, nil
}

// SaveSettings upserts every key Settings carries, in one call, matching the
// admin UI's single "Save" button (spec §9.4: "Save применяет всё разом").
// Nothing is deleted: a key this struct does not know about (there is none
// in v1) would simply never be written, not wiped.
func (s *Store) SaveSettings(set *Settings) error {
	rows := []Setting{
		{Key: settingPanelURL, Value: set.PanelURL},
		{Key: settingMonToken, Value: set.MonToken},
		{Key: settingRealHost, Value: set.RealHost},
		{Key: settingPanelCA, Value: set.PanelCA},
		{Key: settingTgToken, Value: set.TgToken},
		{Key: settingTgChatID, Value: set.TgChatID},

		{Key: settingDownAfter, Value: strconv.Itoa(set.DownAfter)},
		{Key: settingUpAfter, Value: strconv.Itoa(set.UpAfter)},
		{Key: settingFlapN, Value: strconv.Itoa(set.FlapN)},
		{Key: settingFlapMin, Value: strconv.Itoa(set.FlapMin)},
		{Key: settingFlapHoldMin, Value: strconv.Itoa(set.FlapHoldMin)},
		{Key: settingClientOfflineAfter, Value: strconv.Itoa(set.ClientOfflineAfter)},
		{Key: settingPanelDownAfter, Value: strconv.Itoa(set.PanelDownAfter)},

		{Key: settingIntervalMs, Value: strconv.FormatInt(set.IntervalMs, 10)},
		{Key: settingBudgetMs, Value: strconv.FormatInt(set.BudgetMs, 10)},
		{Key: settingConnectMs, Value: strconv.FormatInt(set.ConnectMs, 10)},
		{Key: settingTlsMs, Value: strconv.FormatInt(set.TlsMs, 10)},
		{Key: settingHeadersMs, Value: strconv.FormatInt(set.HeadersMs, 10)},
		{Key: settingStartJitterMs, Value: strconv.FormatInt(set.StartJitterMs, 10)},
		{Key: settingHeartbeatTimeoutMs, Value: strconv.FormatInt(set.HeartbeatTimeoutMs, 10)},
	}

	return s.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&rows).Error
}

// Old and new default of budgetMs (#102), and the settings row that records
// that migrateBudgetDefault has run. The marker is a settings key no
// Settings field reads, so LoadSettings ignores it and SaveSettings, which
// deletes nothing, keeps it.
const (
	oldDefaultBudgetMs           = "20000"
	settingBudgetDefaultMigrated = "migratedBudgetMs30000"
)

// migrateBudgetDefault carries an install onto the 30 s probe budget of
// #102. Save writes every setting (spec §9.4, and the orchestrator posts
// the whole form back), so nearly every running mon-server has the old
// 20 s default stored as budgetMs and would never see the new default. A
// stored "20000" is taken for that old default and rewritten to the new
// one; any other value was chosen by an administrator and is kept. It runs
// once — the marker row is written in the same transaction — so a 20 s
// budget an administrator sets on purpose afterwards survives restarts.
// The documents pick the new budget up on the first panel poll after the
// restart, which rebuilds them all.
func (s *Store) migrateBudgetDefault() error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		var marker int64
		if err := tx.Model(&Setting{}).Where("key = ?", settingBudgetDefaultMigrated).Count(&marker).Error; err != nil {
			return fmt.Errorf("store: read budget migration marker: %w", err)
		}
		if marker > 0 {
			return nil
		}
		newBudget := strconv.FormatInt(DefaultSettings().BudgetMs, 10)
		if err := tx.Model(&Setting{}).Where("key = ? AND value = ?", settingBudgetMs, oldDefaultBudgetMs).
			Update("value", newBudget).Error; err != nil {
			return fmt.Errorf("store: migrate budgetMs default: %w", err)
		}
		return tx.Create(&Setting{Key: settingBudgetDefaultMigrated, Value: "1"}).Error
	})
}

// strOr returns kv[key] if present, else fall back.
func strOr(kv map[string]string, key, fallback string) string {
	if v, ok := kv[key]; ok {
		return v
	}
	return fallback
}

// intOr returns kv[key] parsed as an int if present and well-formed, else
// fall back. A corrupt value (should never happen — only SaveSettings writes
// this table) degrades to the default rather than failing LoadSettings for
// every other key.
func intOr(kv map[string]string, key string, fallback int) int {
	v, ok := kv[key]
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// int64Or is intOr for the ms-duration settings, which are int64 (spec §9.4:
// the Probe tab's *Ms fields) because a probe timeout in milliseconds can
// exceed int32 range in pathological configs and every other ms value in
// mon-server is int64.
func int64Or(kv map[string]string, key string, fallback int64) int64 {
	v, ok := kv[key]
	if !ok {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}
