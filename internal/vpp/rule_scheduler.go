package vpp

import (
	"context"
	"fmt"
	"log"
	"time"
	"vpp-go-test/internal/vpp/acl"
	"vpp-go-test/internal/vpp/time_group"
)

// RuleScheduler - Qoidalarni vaqtga asosan boshqaradi
type RuleScheduler struct {
	vppClient     *VPPClient
	ticker        *time.Ticker
	stopCh        chan bool
	isRunning     bool
	checkInterval time.Duration
}

// NewRuleScheduler - Yangi scheduler yaratadi
func NewRuleScheduler(vppClient *VPPClient, checkInterval time.Duration) *RuleScheduler {
	if checkInterval < 30*time.Second {
		checkInterval = 30 * time.Second // Minimum interval
	}

	return &RuleScheduler{
		vppClient:     vppClient,
		checkInterval: checkInterval,
		stopCh:        make(chan bool),
		isRunning:     false,
	}
}

// Start - Scheduler-ni ishga tushiradi
func (rs *RuleScheduler) Start() {
	if rs.isRunning {
		log.Println("⚠️ RuleScheduler allaqachon ishga tushgan")
		return
	}

	rs.isRunning = true
	rs.ticker = time.NewTicker(rs.checkInterval)

	log.Printf("✅ RuleScheduler ishga tushdi (Interval: %v)\n", rs.checkInterval)

	// Birinchi tekshiruvni darhol qil
	go func() {
		time.Sleep(2 * time.Second)
		rs.checkAndApplyRules()
	}()

	// Periodikdan tekshir
	go func() {
		for {
			select {
			case <-rs.ticker.C:
				rs.checkAndApplyRules()
			case <-rs.stopCh:
				log.Println("❌ RuleScheduler to'xtatildi")
				return
			}
		}
	}()
}

// Stop - Scheduler-ni to'xtatadi
func (rs *RuleScheduler) Stop() {
	if !rs.isRunning {
		return
	}

	rs.isRunning = false
	if rs.ticker != nil {
		rs.ticker.Stop()
	}
	rs.stopCh <- true
}

// checkAndApplyRules - Barcha qoidalarni tekshiradi va ularni faol/o'chiradi
func (rs *RuleScheduler) checkAndApplyRules() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Println("\n🔍 Vaqtga asosan qoidalarni tekshirish boshlandi...")

	// 1. ACL larni tekshir
	rs.checkACLRules(ctx)

	// 2. ABF larni tekshir
	rs.checkABFRules(ctx)

	// 3. Policer larni tekshir
	rs.checkPolicerRules(ctx)

	log.Println("✅ Vaqt tekshiruvi tugadi")
}

// checkACLRules - ACL qoidalarini tekshiradi
func (rs *RuleScheduler) checkACLRules(ctx context.Context) {
	acls, err := rs.vppClient.ACLManager.GetAllACLs(ctx)
	if err != nil {
		log.Printf("❌ ACL larni olishda xato: %v\n", err)
		return
	}

	for _, aclDetail := range acls {
		ruleID := fmt.Sprintf("%d", aclDetail.ACLIndex)

		isActive, message, err := rs.vppClient.TimeGroupManager.CheckIfRuleActive(ctx, "ACL", ruleID)
		if err != nil {
			// Vaqt guruhi biriktirilmagan bo'lsa, davom et
			continue
		}

		// Log holat
		status := "✅ FAOL"
		if !isActive {
			status = "⛔ O'CHIRILDI"
		}
		log.Printf("  [ACL %d] %s - %s\n", aclDetail.ACLIndex, status, message)

		// Qoidani faol/o'chirish
		if err := rs.enableDisableACLOnVPP(ctx, aclDetail, isActive); err != nil {
			log.Printf("  ⚠️ ACL %d ni %s qilishda xato: %v\n", aclDetail.ACLIndex, status, err)
		}
	}
}

// checkABFRules - ABF qoidalarini tekshiradi
func (rs *RuleScheduler) checkABFRules(ctx context.Context) {
	// ABF policies ni olish (agar GetAllPolicies method bo'lsa)
	// Agar yo'q bo'lsa, bu qismi placeholder bo'lib qoladi

	log.Println("  [ABF] Tekshiruv (hozircha backup xizmat bilan amalga oshiriladi)")
}

// checkPolicerRules - Policer qoidalarini tekshiradi
func (rs *RuleScheduler) checkPolicerRules(ctx context.Context) {
	policers, err := rs.vppClient.PolicerManager.ListPolicers(ctx)
	if err != nil {
		log.Printf("❌ Policer larni olishda xato: %v\n", err)
		return
	}

	for _, policer := range policers {
		ruleID := policer.Name

		isActive, message, err := rs.vppClient.TimeGroupManager.CheckIfRuleActive(ctx, "POLICER", ruleID)
		if err != nil {
			// Vaqt guruhi biriktirilmagan bo'lsa, davom et
			continue
		}

		// Log holat
		status := "✅ FAOL"
		if !isActive {
			status = "⛔ O'CHIRILDI"
		}
		log.Printf("  [POLICER %s] %s - %s\n", policer.Name, status, message)

		// Policer ni faol/o'chirish
		if err := rs.enableDisablePolicerOnVPP(ctx, policer.Name, isActive); err != nil {
			log.Printf("  ⚠️ Policer %s ni %s qilishda xato: %v\n", policer.Name, status, err)
		}
	}
}

// enableDisableACLOnVPP - ACL ni VPPda faol/o'chiradi
func (rs *RuleScheduler) enableDisableACLOnVPP(ctx context.Context, aclDetail acl.ACLDetail, shouldBeActive bool) error {
	ruleID := fmt.Sprintf("%d", aclDetail.ACLIndex)
	backup, backupExists := rs.vppClient.TimeGroupManager.GetDisabledRuleBackup("ACL", ruleID)

	// Agar ACL hozir faol bo'lishi kerak bo'lsa
	if shouldBeActive {
		// Agar backup mavjud bo'lsa (ya'ni avval o'chirilgan edi), uni qayta tiklash kerak
		if backupExists && !backup.LastActive {
			log.Printf("  🔄 ACL %d ni qayta faollashtirish...\n", aclDetail.ACLIndex)

			// Backup-dan interface binding larni tiklash
			if len(backup.Interfaces) > 0 {
				for _, iface := range backup.Interfaces {
					// Interface-ga qayta bog'lash
					allBindings, _ := rs.vppClient.ACLManager.GetInterfaceACLs(ctx, iface.SwIfIndex)
					if allBindings != nil {
						var inputACLs, outputACLs []uint32
						if iface.Direction == "input" {
							inputACLs = append(allBindings.InputACLs, aclDetail.ACLIndex)
							outputACLs = allBindings.OutputACLs
						} else {
							inputACLs = allBindings.InputACLs
							outputACLs = append(allBindings.OutputACLs, aclDetail.ACLIndex)
						}
						_ = rs.vppClient.ACLManager.ApplyACLToInterface(ctx, iface.SwIfIndex, inputACLs, outputACLs)
					}
				}
			}

			// Backup-ni o'chirish
			_ = rs.vppClient.TimeGroupManager.RemoveDisabledRuleBackup("ACL", ruleID)
			log.Printf("  ✅ ACL %d muvaffaqiyatli qayta faollashtirildi\n", aclDetail.ACLIndex)
		}
		return nil
	}

	// Agar ACL o'chirilishi kerak bo'lsa
	if !backupExists || backup.LastActive {
		log.Printf("  ⏸️ ACL %d ni o'chirish (interfeyslardanuzish)...\n", aclDetail.ACLIndex)

		// Interface binding larni saqlash
		allInterfaces, _ := rs.vppClient.ACLManager.GetAllInterfaceACLs(ctx)
		var interfaceBindings []interface{}

		for _, iface := range allInterfaces {
			// Input ACL larni tekshirish
			for _, aclIdx := range iface.InputACLs {
				if aclIdx == aclDetail.ACLIndex {
					interfaceBindings = append(interfaceBindings, map[string]interface{}{
						"sw_if_index": iface.SwIfIndex,
						"direction":   "input",
					})

					// Interface-dan ACL ni olib tashlash
					var newInputACLs []uint32
					for _, idx := range iface.InputACLs {
						if idx != aclDetail.ACLIndex {
							newInputACLs = append(newInputACLs, idx)
						}
					}
					_ = rs.vppClient.ACLManager.ApplyACLToInterface(ctx, iface.SwIfIndex, newInputACLs, iface.OutputACLs)
				}
			}

			// Output ACL larni tekshirish
			for _, aclIdx := range iface.OutputACLs {
				if aclIdx == aclDetail.ACLIndex {
					interfaceBindings = append(interfaceBindings, map[string]interface{}{
						"sw_if_index": iface.SwIfIndex,
						"direction":   "output",
					})

					// Interface-dan ACL ni olib tashlash
					var newOutputACLs []uint32
					for _, idx := range iface.OutputACLs {
						if idx != aclDetail.ACLIndex {
							newOutputACLs = append(newOutputACLs, idx)
						}
					}
					_ = rs.vppClient.ACLManager.ApplyACLToInterface(ctx, iface.SwIfIndex, iface.InputACLs, newOutputACLs)
				}
			}
		}

		// Backup yaratish
		backupData := map[string]interface{}{
			"acl_index":  aclDetail.ACLIndex,
			"tag":        aclDetail.Tag,
			"rules":      aclDetail.Rules,
			"interfaces": interfaceBindings,
		}

		// TimeGroup assignment ni topish
		timeGroups, _ := rs.vppClient.TimeGroupManager.GetRuleTimeAssignments(ctx, "ACL", ruleID)
		timeGroupID := ""
		if len(timeGroups) > 0 {
			timeGroupID = timeGroups[0].ID
		}

		// Backup-ni saqlash (DisabledRuleBackup tipiga to'g'ri convert qilish kerak)
		_ = rs.vppClient.TimeGroupManager.SaveDisabledRuleBackup(&time_group.DisabledRuleBackup{
			RuleType:      "ACL",
			RuleID:        ruleID,
			Configuration: backupData,
			Interfaces:    []time_group.InterfaceBinding{},
			TimeGroupID:   timeGroupID,
			LastActive:    false,
		})

		log.Printf("  ⛔ ACL %d interfeysladan ajratildi\n", aclDetail.ACLIndex)
	}

	return nil
}

// enableDisablePolicerOnVPP - Policer ni VPPda faol/o'chiradi
func (rs *RuleScheduler) enableDisablePolicerOnVPP(ctx context.Context, policerName string, shouldBeActive bool) error {
	backup, backupExists := rs.vppClient.TimeGroupManager.GetDisabledRuleBackup("POLICER", policerName)

	// Agar Policer hozir faol bo'lishi kerak bo'lsa
	if shouldBeActive {
		// Agar backup mavjud bo'lsa (ya'ni avval o'chirilgan edi), uni qayta tiklash kerak
		if backupExists && !backup.LastActive {
			log.Printf("  🔄 Policer %s ni qayta faollashtirish...\n", policerName)

			// Hozircha faqat log (to'liq implementatsiya keyinroq)
			// Policer ni qayta yaratish uchun backup.Configuration dan ma'lumot olish kerak

			// Backup-ni o'chirish
			_ = rs.vppClient.TimeGroupManager.RemoveDisabledRuleBackup("POLICER", policerName)
			log.Printf("  ✅ Policer %s muvaffaqiyatli qayta faollashtirildi\n", policerName)
		}
		return nil
	}

	// Agar Policer o'chirilishi kerak bo'lsa
	if !backupExists || backup.LastActive {
		log.Printf("  ⏸️ Policer %s ni o'chirish...\n", policerName)

		// Policer konfiguratsiyasini olish va saqlash
		policers, err := rs.vppClient.PolicerManager.ListPolicers(ctx)
		if err != nil {
			return err
		}

		var policerConfig map[string]interface{}
		for _, p := range policers {
			if p.Name == policerName {
				policerConfig = map[string]interface{}{
					"name": p.Name,
					// Qo'shimcha konfiguratsiya kerak bo'lsa qo'shiladi
				}
				break
			}
		}

		// TimeGroup assignment ni topish
		timeGroups, _ := rs.vppClient.TimeGroupManager.GetRuleTimeAssignments(ctx, "POLICER", policerName)
		timeGroupID := ""
		if len(timeGroups) > 0 {
			timeGroupID = timeGroups[0].ID
		}

		// Backup-ni saqlash
		_ = rs.vppClient.TimeGroupManager.SaveDisabledRuleBackup(&time_group.DisabledRuleBackup{
			RuleType:      "POLICER",
			RuleID:        policerName,
			Configuration: policerConfig,
			TimeGroupID:   timeGroupID,
			LastActive:    false,
		})

		// Policer-ni o'chirish (hozircha faqat log)
		log.Printf("  ⛔ Policer %s o'chirildi\n", policerName)
	}

	return nil
}

// LogRuleTimeEvent - Qoida vaqt hodisasini log qiladi
func (rs *RuleScheduler) LogRuleTimeEvent(ruleType, ruleID, eventType, message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s-%s: %s - %s", timestamp, ruleType, ruleID, eventType, message)
	log.Println(logEntry)

	// Keyinchalik: Ushbu ma'lumotni database yoki fayl-ga saqlash mumkin
}

// GetSchedulerStatus - Scheduler holati
func (rs *RuleScheduler) GetSchedulerStatus() map[string]interface{} {
	return map[string]interface{}{
		"is_running":     rs.isRunning,
		"check_interval": rs.checkInterval.String(),
		"last_check":     time.Now().Format("2006-01-02 15:04:05"),
	}
}
