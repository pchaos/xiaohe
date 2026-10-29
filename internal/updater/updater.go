// Package updater reports the license state for the UI. The old remote
// update feed (version.json manifest + bundle download) has been removed:
// Xiaohe never downloads GUI or core updates from a third-party address at
// runtime. Core upgrades happen at build/release time from the official
// CluvexStudio/Aether releases only, and users replace binaries manually.
//
// Xiaohe is unconditionally licensed: LicenseStatus always reports
// unlimited use, and a machine that cannot reach the network is never
// locked out.
package updater

// License is the license state shown in the UI. Xiaohe is unconditionally
// licensed: DaysLeft is always -1 (unlimited), which the UI renders as
// "无限制". Kept as a struct so the JSON shape stays stable.
type License struct {
	DaysLeft int `json:"days_left"` // -1 = unlimited
}

// LicenseStatus reports the license state. Xiaohe is unconditionally
// licensed: the old remote trial/expiry window is removed, so every build
// reports unlimited use and the UI never shows an expiry wall.
func LicenseStatus() License {
	return License{DaysLeft: -1} // -1 = unlimited/unknown; UI renders "无限制"
}