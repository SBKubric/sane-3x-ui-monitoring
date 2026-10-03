package store

import "testing"

// TestLoadSettings_DefaultsOnEmptyTable checks that an install that has never
// saved a setting gets exactly the spec's defaults (§9.4), not zero values —
// a fresh mon-server must poll every 60s and treat 3 consecutive failures as
// DOWN out of the box, before anyone has ever opened the admin UI.
func TestLoadSettings_DefaultsOnEmptyTable(t *testing.T) {
	s := openTestStore(t)

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	want := DefaultSettings()
	if *got != *want {
		t.Fatalf("LoadSettings() = %+v, want defaults %+v", got, want)
	}
}

// TestSettings_RoundTrip checks that SaveSettings followed by LoadSettings
// returns exactly what was saved, across every field including the string
// settings that have no default (panelUrl, monToken, ...).
func TestSettings_RoundTrip(t *testing.T) {
	s := openTestStore(t)

	want := &Settings{
		PanelURL: "https://panel.example:2053/base/",
		MonToken: "secret-token",
		RealHost: "real.example.com",
		PanelCA:  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		TgToken:  "bot:token",
		TgChatID: "-100123456",

		DownAfter:          5,
		UpAfter:            1,
		FlapN:              6,
		FlapMin:            45,
		FlapHoldMin:        20,
		ClientOfflineAfter: 4,
		PanelDownAfter:     2,

		IntervalMs:         30000,
		BudgetMs:           15000,
		ConnectMs:          4000,
		TlsMs:              8000,
		HeadersMs:          9000,
		StartJitterMs:      2000,
		HeartbeatTimeoutMs: 7000,
	}

	if err := s.SaveSettings(want); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if *got != *want {
		t.Fatalf("LoadSettings() after SaveSettings = %+v, want %+v", got, want)
	}
}

// TestSettings_PartialSaveKeepsOtherDefaults checks that saving once, then
// loading, still reports spec defaults for keys the caller never mentioned —
// LoadSettings must not confuse "an empty settings table" with "a table
// where only some keys are missing".
func TestSettings_PartialSaveKeepsOtherDefaults(t *testing.T) {
	s := openTestStore(t)

	first := DefaultSettings()
	first.PanelURL = "https://panel.example/"
	if err := s.SaveSettings(first); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.PanelURL != "https://panel.example/" {
		t.Fatalf("PanelURL = %q, want saved value", got.PanelURL)
	}
	if got.DownAfter != DefaultSettings().DownAfter {
		t.Fatalf("DownAfter = %d, want default %d", got.DownAfter, DefaultSettings().DownAfter)
	}
}

// TestSaveSettings_Upserts checks that saving twice updates in place rather
// than erroring or duplicating rows — the admin UI's Save button is called
// repeatedly against the same keys for the life of the install.
func TestSaveSettings_Upserts(t *testing.T) {
	s := openTestStore(t)

	set := DefaultSettings()
	set.DownAfter = 3
	if err := s.SaveSettings(set); err != nil {
		t.Fatalf("first SaveSettings: %v", err)
	}
	set.DownAfter = 9
	if err := s.SaveSettings(set); err != nil {
		t.Fatalf("second SaveSettings: %v", err)
	}

	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.DownAfter != 9 {
		t.Fatalf("DownAfter = %d, want 9 after second save", got.DownAfter)
	}

	var count int64
	if err := s.DB.Model(&Setting{}).Where("key = ?", settingDownAfter).Count(&count).Error; err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("row count for %s = %d, want 1 (upsert, not duplicate)", settingDownAfter, count)
	}
}

// TestMigrate_BudgetDefault is #102: the probe budget's default went from
// 20 s to 30 s, and since Save writes every setting, an install that ever
// saved the form has the old default stored. Migrate rewrites a stored
// "20000" once; an administrator's own value is kept, and so is a 20 s
// budget set on purpose after the migration ran.
func TestMigrate_BudgetDefault(t *testing.T) {
	t.Run("old default is rewritten", func(t *testing.T) {
		s := openTestStore(t)
		// openTestStore already migrated an empty table; drop the marker
		// to stand in for a database from before #102.
		if err := s.DB.Where("key = ?", settingBudgetDefaultMigrated).Delete(&Setting{}).Error; err != nil {
			t.Fatalf("drop marker: %v", err)
		}
		set := DefaultSettings()
		set.BudgetMs = 20000
		if err := s.SaveSettings(set); err != nil {
			t.Fatalf("SaveSettings: %v", err)
		}
		if err := s.Migrate(); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if got := loadBudget(t, s); got != 30000 {
			t.Errorf("budgetMs = %d, want 30000", got)
		}

		// A 20 s budget chosen after the migration survives a restart.
		set.BudgetMs = 20000
		if err := s.SaveSettings(set); err != nil {
			t.Fatalf("SaveSettings: %v", err)
		}
		if err := s.Migrate(); err != nil {
			t.Fatalf("Migrate again: %v", err)
		}
		if got := loadBudget(t, s); got != 20000 {
			t.Errorf("budgetMs = %d after a second Migrate, want the administrator's 20000 kept", got)
		}
	})

	t.Run("administrator's value is kept", func(t *testing.T) {
		s := openTestStore(t)
		if err := s.DB.Where("key = ?", settingBudgetDefaultMigrated).Delete(&Setting{}).Error; err != nil {
			t.Fatalf("drop marker: %v", err)
		}
		set := DefaultSettings()
		set.BudgetMs = 25000
		if err := s.SaveSettings(set); err != nil {
			t.Fatalf("SaveSettings: %v", err)
		}
		if err := s.Migrate(); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if got := loadBudget(t, s); got != 25000 {
			t.Errorf("budgetMs = %d, want 25000 kept", got)
		}
	})

	t.Run("fresh install gets the new default", func(t *testing.T) {
		s := openTestStore(t)
		if got := loadBudget(t, s); got != 30000 {
			t.Errorf("budgetMs = %d, want 30000", got)
		}
	})
}

func loadBudget(t *testing.T, s *Store) int64 {
	t.Helper()
	got, err := s.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	return got.BudgetMs
}
