package vpp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
	"vpp-go-test/binapi/acl_types"
	"vpp-go-test/binapi/ip_types"
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

	// 0. Pending ACL qoidalarni tekshir (vaqt guruhi faol bo'lgan bo'lsa, VPPga push qilish)
	rs.checkPendingACLRules(ctx)

	// 1. ACL larni tekshir
	rs.checkACLRules(ctx)

	// 2. ABF larni tekshir
	rs.checkABFRules(ctx)

	// 3. Policer larni tekshir
	rs.checkPolicerRules(ctx)

	log.Println("✅ Vaqt tekshiruvi tugadi")
}

// checkPendingACLRules - Pending (VPPga push qilinmagan) ACL qoidalarni tekshiradi
func (rs *RuleScheduler) checkPendingACLRules(ctx context.Context) {
	pendingRules := rs.vppClient.TimeGroupManager.ListPendingACLRules()

	if len(pendingRules) == 0 {
		return
	}

	log.Printf("  📋 %d ta pending ACL qoida topildi\n", len(pendingRules))

	for _, pending := range pendingRules {
		// Vaqt guruhi hozir faol ekanligini tekshirish
		if rs.vppClient.TimeGroupManager.IsTimeGroupActiveNow(pending.TimeGroupID) {
			log.Printf("  🚀 Pending ACL '%s' ni VPPga push qilish (vaqt guruhi faol)...\n", pending.Tag)

			// WebInput formatidan VPP ACLRule formatiga o'girish
			var vppRules []acl_types.ACLRule
			for _, ruleMap := range pending.Rules {
				// JSON orqali WebInput ga convert qilish
				ruleBytes, _ := json.Marshal(ruleMap)
				var webInput acl.WebInput
				if err := json.Unmarshal(ruleBytes, &webInput); err != nil {
					log.Printf("    ⚠️ Rule JSON parsing xato: %v\n", err)
					continue
				}

				vppRule, err := acl.CreateRuleFromWebInput(webInput, pending.IsStateful)
				if err != nil {
					log.Printf("    ⚠️ VPP Rule yaratishda xato: %v\n", err)
					continue
				}
				vppRules = append(vppRules, vppRule)
			}

			// VPPga ACL yaratish
			aclIndex, err := rs.vppClient.ACLManager.CreateACL(ctx, pending.Tag, vppRules)
			if err != nil {
				log.Printf("    ❌ VPPga ACL yaratishda xato: %v\n", err)
				continue
			}

			// Time group tayinlash
			aclID := fmt.Sprintf("%d", aclIndex)
			_ = rs.vppClient.TimeGroupManager.AssignTimeGroupToRule(ctx, "ACL", aclID, pending.TimeGroupID)

			// Pending dan o'chirish
			_ = rs.vppClient.TimeGroupManager.RemovePendingACLRule(pending.ID)

			log.Printf("    ✅ ACL %d muvaffaqiyatli yaratildi (tag: %s)\n", aclIndex, pending.Tag)
		}
	}
}

// checkACLRules - ACL qoidalarini tekshiradi
func (rs *RuleScheduler) checkACLRules(ctx context.Context) {
	// 1. VPP dagi ACL larni tekshir
	acls, err := rs.vppClient.ACLManager.GetAllACLs(ctx)
	if err != nil {
		log.Printf("❌ ACL larni olishda xato: %v\n", err)
		return
	}

	// VPP dagi ACL larni qayta ishlash
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

	// 2. Backup dagi ACL larni tekshir (VPP da yo'q, lekin vaqt kelganda qayta yoqilishi kerak)
	rs.checkDisabledACLBackups(ctx)
}

// checkDisabledACLBackups - Disabled backup dagi ACL larni tekshiradi va vaqt kelganda qayta yoqadi
func (rs *RuleScheduler) checkDisabledACLBackups(ctx context.Context) {
	backups := rs.vppClient.TimeGroupManager.ListDisabledRuleBackups()

	for key, backup := range backups {
		// Faqat ACL turini tekshirish
		if backup.RuleType != "ACL" {
			continue
		}

		// Vaqt guruhi hozir faol ekanligini tekshirish
		isActive, message, err := rs.vppClient.TimeGroupManager.CheckIfRuleActive(ctx, "ACL", backup.RuleID)
		if err != nil {
			continue
		}

		if isActive && !backup.LastActive {
			log.Printf("  🔄 Backup ACL %s ni qayta faollashtirish (vaqt guruhi faol bo'ldi)...\n", backup.RuleID)

			// ACL VPP da mavjudligini tekshirish
			acls, _ := rs.vppClient.ACLManager.GetAllACLs(ctx)
			aclFound := false
			var foundACL acl.ACLDetail

			for _, aclDetail := range acls {
				if fmt.Sprintf("%d", aclDetail.ACLIndex) == backup.RuleID {
					aclFound = true
					foundACL = aclDetail
					break
				}
			}

			var aclIndexToUse uint32

			if aclFound {
				// ACL VPP da mavjud - interface bindinglarni tiklash
				log.Printf("    ACL %s VPP da mavjud, interface bindinglarni tiklash...\n", backup.RuleID)
				aclIndexToUse = foundACL.ACLIndex
			} else {
				// ACL VPP da mavjud emas - backupdan qayta yaratish
				log.Printf("    🔨 ACL %s VPP da topilmadi, backupdan qayta yaratish...\n", backup.RuleID)

				// Configuration dan ma'lumotlarni olish
				config := backup.Configuration
				tag, _ := config["tag"].(string)
				rulesRaw, _ := config["rules"].([]interface{})

				if len(rulesRaw) == 0 {
					log.Printf("    ❌ Backupda rules topilmadi\n")
					continue
				}

				// Rules ni VPP formatiga o'tkazish
				var vppRules []acl_types.ACLRule
				for _, ruleRaw := range rulesRaw {
					ruleMap, ok := ruleRaw.(map[string]interface{})
					if !ok {
						continue
					}

					srcPrefix, err := acl.ParseCIDR(getStringFromMap(ruleMap, "src_prefix", "0.0.0.0/0"))
					if err != nil {
						log.Printf("    ⚠️ src_prefix parse xato: %v\n", err)
						continue
					}

					dstPrefix, err := acl.ParseCIDR(getStringFromMap(ruleMap, "dst_prefix", "0.0.0.0/0"))
					if err != nil {
						log.Printf("    ⚠️ dst_prefix parse xato: %v\n", err)
						continue
					}

					vppRule := acl_types.ACLRule{
						IsPermit:               acl_types.ACLAction(getUint8FromMap(ruleMap, "is_permit")),
						SrcPrefix:              srcPrefix,
						DstPrefix:              dstPrefix,
						Proto:                  ip_types.IPProto(getUint8FromMap(ruleMap, "proto")),
						SrcportOrIcmptypeFirst: getUint16FromMap(ruleMap, "srcport_or_icmptype_first"),
						SrcportOrIcmptypeLast:  getUint16FromMap(ruleMap, "srcport_or_icmptype_last"),
						DstportOrIcmpcodeFirst: getUint16FromMap(ruleMap, "dstport_or_icmpcode_first"),
						DstportOrIcmpcodeLast:  getUint16FromMap(ruleMap, "dstport_or_icmpcode_last"),
						TCPFlagsMask:           getUint8FromMap(ruleMap, "tcp_flags_mask"),
						TCPFlagsValue:          getUint8FromMap(ruleMap, "tcp_flags_value"),
					}
					vppRules = append(vppRules, vppRule)
				}

				if len(vppRules) == 0 {
					log.Printf("    ❌ VPP rules yaratib bo'lmadi\n")
					continue
				}

				// ACL ni VPP da yaratish
				newACLIndex, err := rs.vppClient.ACLManager.CreateACL(ctx, tag, vppRules)
				if err != nil {
					log.Printf("    ❌ ACL yaratishda xato: %v\n", err)
					continue
				}

				log.Printf("    ✅ ACL '%s' VPP da yaratildi (yangi index: %d)\n", tag, newACLIndex)
				aclIndexToUse = newACLIndex

				// Assignment ni yangi index bilan yangilash
				rs.vppClient.TimeGroupManager.UpdateRuleAssignmentID("ACL", backup.RuleID, fmt.Sprintf("%d", newACLIndex))

				// Backup dan time_group_id ni tiklash
				if backup.TimeGroupID != "" {
					err := rs.vppClient.TimeGroupManager.AssignTimeGroupToRule(ctx, backup.TimeGroupID, "ACL", fmt.Sprintf("%d", newACLIndex))
					if err != nil {
						log.Printf("    ⚠️ TimeGroup assignment tiklashda xato: %v\n", err)
					} else {
						log.Printf("    ✅ TimeGroup %s tayinlandi\n", backup.TimeGroupID)
					}
				}
			}

			// Interface bindinglarni tiklash
			if len(backup.Interfaces) > 0 {
				for _, iface := range backup.Interfaces {
					log.Printf("    ↳ Interface %d ga %s sifatida qayta bog'lash...\n", iface.SwIfIndex, iface.Direction)

					currentBindings, err := rs.vppClient.ACLManager.GetInterfaceACLs(ctx, iface.SwIfIndex)
					if err != nil {
						currentBindings = &acl.InterfaceACLMap{
							SwIfIndex:  iface.SwIfIndex,
							InputACLs:  []uint32{},
							OutputACLs: []uint32{},
						}
					}

					var newInputACLs, newOutputACLs []uint32

					if iface.Direction == "input" {
						alreadyExists := false
						for _, idx := range currentBindings.InputACLs {
							if idx == aclIndexToUse {
								alreadyExists = true
								break
							}
						}
						if !alreadyExists {
							newInputACLs = append(currentBindings.InputACLs, aclIndexToUse)
						} else {
							newInputACLs = currentBindings.InputACLs
						}
						newOutputACLs = currentBindings.OutputACLs
					} else {
						newInputACLs = currentBindings.InputACLs
						alreadyExists := false
						for _, idx := range currentBindings.OutputACLs {
							if idx == aclIndexToUse {
								alreadyExists = true
								break
							}
						}
						if !alreadyExists {
							newOutputACLs = append(currentBindings.OutputACLs, aclIndexToUse)
						} else {
							newOutputACLs = currentBindings.OutputACLs
						}
					}

					if err := rs.vppClient.ACLManager.ApplyACLToInterface(ctx, iface.SwIfIndex, newInputACLs, newOutputACLs); err != nil {
						log.Printf("    ❌ Interface %d ga bog'lashda xato: %v\n", iface.SwIfIndex, err)
					} else {
						log.Printf("    ✅ Interface %d ga muvaffaqiyatli bog'landi\n", iface.SwIfIndex)
					}
				}
			}

			// Backup-ni o'chirish
			_ = rs.vppClient.TimeGroupManager.RemoveDisabledRuleBackup("ACL", backup.RuleID)
			log.Printf("  ✅ ACL %s muvaffaqiyatli qayta faollashtirildi\n", backup.RuleID)
		} else if !isActive {
			log.Printf("  [Backup ACL %s] ⛔ - %s\n", key, message)
		}
	}
}

// checkABFRules - ABF qoidalarini tekshiradi
func (rs *RuleScheduler) checkABFRules(ctx context.Context) {
	policies, err := rs.vppClient.AbfManager.ListPolicies(ctx)
	if err != nil {
		log.Printf("❌ ABF policies olishda xato: %v\n", err)
		return
	}

	for _, policy := range policies {
		ruleID := fmt.Sprintf("%d", policy.Policy.PolicyID)

		isActive, message, err := rs.vppClient.TimeGroupManager.CheckIfRuleActive(ctx, "ABF", ruleID)
		if err != nil {
			// Vaqt guruhi biriktirilmagan bo'lsa, davom et
			continue
		}

		// Log holat
		status := "✅ FAOL"
		if !isActive {
			status = "⛔ O'CHIRILDI"
		}
		log.Printf("  [ABF Policy %d] %s - %s\n", policy.Policy.PolicyID, status, message)

		// ABF ni faol/o'chirish
		if err := rs.enableDisableABFOnVPP(ctx, policy.Policy.PolicyID, isActive); err != nil {
			log.Printf("  ⚠️ ABF Policy %d ni %s qilishda xato: %v\n", policy.Policy.PolicyID, status, err)
		}
	}
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

	log.Printf("    [DEBUG] ACL %d: shouldBeActive=%v, backupExists=%v, backup.LastActive=%v\n",
		aclDetail.ACLIndex, shouldBeActive, backupExists, func() bool {
			if backup != nil {
				return backup.LastActive
			}
			return false
		}())

	// ========== FAOLLASHTIRISH ==========
	if shouldBeActive {
		// Backup mavjud va LastActive=false bo'lsa - avval o'chirilgan, endi qayta yoqish kerak
		if backupExists && backup != nil && !backup.LastActive {
			log.Printf("  🔄 ACL %d ni qayta faollashtirish (backup topildi, %d ta interface binding)...\n",
				aclDetail.ACLIndex, len(backup.Interfaces))

			// Backup-dan interface binding larni tiklash
			if len(backup.Interfaces) > 0 {
				for _, iface := range backup.Interfaces {
					log.Printf("    ↳ Interface %d ga %s sifatida qayta bog'lash...\n", iface.SwIfIndex, iface.Direction)

					// Hozirgi interface bindinglarni olish
					currentBindings, err := rs.vppClient.ACLManager.GetInterfaceACLs(ctx, iface.SwIfIndex)
					if err != nil {
						log.Printf("    ⚠️ Interface %d bindinglarini olishda xato: %v\n", iface.SwIfIndex, err)
						// Xato bo'lsa ham, yangi binding qilishni urinib ko'ramiz
						currentBindings = &acl.InterfaceACLMap{
							SwIfIndex:  iface.SwIfIndex,
							InputACLs:  []uint32{},
							OutputACLs: []uint32{},
						}
					}

					var newInputACLs, newOutputACLs []uint32

					if iface.Direction == "input" {
						// Dublikat tekshirish
						alreadyExists := false
						for _, idx := range currentBindings.InputACLs {
							if idx == aclDetail.ACLIndex {
								alreadyExists = true
								break
							}
						}
						if alreadyExists {
							log.Printf("    ℹ️ ACL %d allaqachon interface %d input da mavjud\n", aclDetail.ACLIndex, iface.SwIfIndex)
							continue
						}
						newInputACLs = append(currentBindings.InputACLs, aclDetail.ACLIndex)
						newOutputACLs = currentBindings.OutputACLs
					} else {
						// Dublikat tekshirish
						alreadyExists := false
						for _, idx := range currentBindings.OutputACLs {
							if idx == aclDetail.ACLIndex {
								alreadyExists = true
								break
							}
						}
						if alreadyExists {
							log.Printf("    ℹ️ ACL %d allaqachon interface %d output da mavjud\n", aclDetail.ACLIndex, iface.SwIfIndex)
							continue
						}
						newInputACLs = currentBindings.InputACLs
						newOutputACLs = append(currentBindings.OutputACLs, aclDetail.ACLIndex)
					}

					log.Printf("    📌 ApplyACLToInterface: sw_if_index=%d, input=%v, output=%v\n",
						iface.SwIfIndex, newInputACLs, newOutputACLs)

					if err := rs.vppClient.ACLManager.ApplyACLToInterface(ctx, iface.SwIfIndex, newInputACLs, newOutputACLs); err != nil {
						log.Printf("    ❌ Interface %d ga bog'lashda xato: %v\n", iface.SwIfIndex, err)
					} else {
						log.Printf("    ✅ Interface %d ga muvaffaqiyatli bog'landi\n", iface.SwIfIndex)
					}
				}
			} else {
				log.Printf("    ℹ️ ACL %d uchun saqlangan interface binding yo'q\n", aclDetail.ACLIndex)
			}

			// Backup-ni o'chirish
			if err := rs.vppClient.TimeGroupManager.RemoveDisabledRuleBackup("ACL", ruleID); err != nil {
				log.Printf("    ⚠️ Backup o'chirishda xato: %v\n", err)
			}
			log.Printf("  ✅ ACL %d muvaffaqiyatli qayta faollashtirildi\n", aclDetail.ACLIndex)
		}
		return nil
	}

	// ========== O'CHIRISH ==========
	// Faqat backup mavjud emas YOKI oxirgi marta faol bo'lgan bo'lsa o'chirish
	if !backupExists {
		log.Printf("  ⏸️ ACL %d ni o'chirish (backup mavjud emas)...\n", aclDetail.ACLIndex)
	} else if backup != nil && backup.LastActive {
		log.Printf("  ⏸️ ACL %d ni o'chirish (LastActive=true)...\n", aclDetail.ACLIndex)
	} else {
		// Backup allaqachon mavjud va LastActive=false - allaqachon o'chirilgan
		log.Printf("    ℹ️ ACL %d allaqachon o'chirilgan (backup mavjud)\n", aclDetail.ACLIndex)
		return nil
	}

	// Interface binding larni saqlash
	allInterfaces, err := rs.vppClient.ACLManager.GetAllInterfaceACLs(ctx)
	if err != nil {
		log.Printf("    ⚠️ Interface ACL larni olishda xato: %v\n", err)
		allInterfaces = []acl.InterfaceACLMap{}
	}

	var interfaceBindings []time_group.InterfaceBinding

	for _, iface := range allInterfaces {
		// Input ACL larni tekshirish
		hasInputBinding := false
		for _, aclIdx := range iface.InputACLs {
			if aclIdx == aclDetail.ACLIndex {
				hasInputBinding = true
				break
			}
		}

		if hasInputBinding {
			interfaceBindings = append(interfaceBindings, time_group.InterfaceBinding{
				SwIfIndex: iface.SwIfIndex,
				Direction: "input",
			})

			// Interface-dan ACL ni olib tashlash
			var newInputACLs []uint32
			for _, idx := range iface.InputACLs {
				if idx != aclDetail.ACLIndex {
					newInputACLs = append(newInputACLs, idx)
				}
			}

			log.Printf("    🔓 Interface %d dan input ACL %d ni uzish...\n", iface.SwIfIndex, aclDetail.ACLIndex)
			if err := rs.vppClient.ACLManager.ApplyACLToInterface(ctx, iface.SwIfIndex, newInputACLs, iface.OutputACLs); err != nil {
				log.Printf("    ❌ Interface %d dan uzishda xato: %v\n", iface.SwIfIndex, err)
			}
		}

		// Output ACL larni tekshirish
		hasOutputBinding := false
		for _, aclIdx := range iface.OutputACLs {
			if aclIdx == aclDetail.ACLIndex {
				hasOutputBinding = true
				break
			}
		}

		if hasOutputBinding {
			interfaceBindings = append(interfaceBindings, time_group.InterfaceBinding{
				SwIfIndex: iface.SwIfIndex,
				Direction: "output",
			})

			// Interface-dan ACL ni olib tashlash
			var newOutputACLs []uint32
			for _, idx := range iface.OutputACLs {
				if idx != aclDetail.ACLIndex {
					newOutputACLs = append(newOutputACLs, idx)
				}
			}

			log.Printf("    🔓 Interface %d dan output ACL %d ni uzish...\n", iface.SwIfIndex, aclDetail.ACLIndex)
			if err := rs.vppClient.ACLManager.ApplyACLToInterface(ctx, iface.SwIfIndex, iface.InputACLs, newOutputACLs); err != nil {
				log.Printf("    ❌ Interface %d dan uzishda xato: %v\n", iface.SwIfIndex, err)
			}
		}
	}

	// TimeGroup assignment ni topish
	timeGroups, _ := rs.vppClient.TimeGroupManager.GetRuleTimeAssignments(ctx, "ACL", ruleID)
	timeGroupID := ""
	if len(timeGroups) > 0 {
		timeGroupID = timeGroups[0].ID
	}

	// Backup-ni saqlash
	backupToSave := &time_group.DisabledRuleBackup{
		RuleType: "ACL",
		RuleID:   ruleID,
		Configuration: map[string]interface{}{
			"acl_index": aclDetail.ACLIndex,
			"tag":       aclDetail.Tag,
			"rules":     aclDetail.Rules,
		},
		Interfaces:  interfaceBindings,
		TimeGroupID: timeGroupID,
		LastActive:  false,
	}

	if err := rs.vppClient.TimeGroupManager.SaveDisabledRuleBackup(backupToSave); err != nil {
		log.Printf("    ❌ Backup saqlashda xato: %v\n", err)
	}

	log.Printf("  ⛔ ACL %d interfeysladan ajratildi (%d ta binding saqlandi)\n", aclDetail.ACLIndex, len(interfaceBindings))
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

			// Backup-dan konfiguratsiyani olish
			if config, ok := backup.Configuration["config"].(map[string]interface{}); ok {
				cir, _ := rs.asUint32(config["cir"])
				cb, _ := rs.asUint64(config["cb"])

				// Policer ni VPP-da qayta yaratish
				_, err := rs.vppClient.PolicerManager.AddPolicer(ctx, policerName, cir, cb)
				if err != nil {
					log.Printf("  ❌ Policer %s ni qayta yaratishda xato: %v\n", policerName, err)
					return err
				}

				// Interface binding larni tiklash
				if bindings, ok := backup.Configuration["bindings"].([]interface{}); ok {
					for _, b := range bindings {
						if binding, ok := b.(map[string]interface{}); ok {
							swIfIndex, err := rs.asUint32(binding["sw_if_index"])
							if err != nil {
								log.Printf("  ⚠️ Policer binding sw_if_index xato: %v\n", err)
								continue
							}
							direction, err := rs.asString(binding["direction"])
							if err != nil {
								log.Printf("  ⚠️ Policer binding direction xato: %v\n", err)
								continue
							}
							_ = rs.vppClient.PolicerManager.BindToInterface(ctx, policerName, swIfIndex, direction, true)
						}
					}
				}
			}

			// Backup-ni o'chirish
			_ = rs.vppClient.TimeGroupManager.RemoveDisabledRuleBackup("POLICER", policerName)
			log.Printf("  ✅ Policer %s muvaffaqiyatli VPP-da qayta yaratildi\n", policerName)
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
		var bindings []interface{}
		for _, p := range policers {
			if p.Name == policerName {
				policerConfig = map[string]interface{}{
					"cir": p.Cir,
					"cb":  p.Cb,
				}
				break
			}
		}

		// Interface binding larni o'zimiz saqlab boramiz (VPPda dump API yo'q)
		for _, b := range rs.vppClient.PolicerManager.GetBindingsForPolicer(policerName) {
			bindings = append(bindings, map[string]interface{}{
				"sw_if_index": b.SwIfIndex,
				"direction":   b.Direction,
			})
		}

		// TimeGroup assignment ni topish
		timeGroups, _ := rs.vppClient.TimeGroupManager.GetRuleTimeAssignments(ctx, "POLICER", policerName)
		timeGroupID := ""
		if len(timeGroups) > 0 {
			timeGroupID = timeGroups[0].ID
		}

		// Backup-ni saqlash
		_ = rs.vppClient.TimeGroupManager.SaveDisabledRuleBackup(&time_group.DisabledRuleBackup{
			RuleType: "POLICER",
			RuleID:   policerName,
			Configuration: map[string]interface{}{
				"config":   policerConfig,
				"bindings": bindings,
			},
			TimeGroupID: timeGroupID,
			LastActive:  false,
		})

		// Policer-ni VPP-dan o'chirish (nomi bo'yicha)
		if err := rs.vppClient.PolicerManager.DeletePolicerByName(ctx, policerName); err != nil {
			log.Printf("  ❌ Policer %s ni VPP-dan o'chirishda xato: %v\n", policerName, err)
			return err
		}

		log.Printf("  ⛔ Policer %s VPP-dan o'chirildi\n", policerName)
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

// enableDisableABFOnVPP - ABF Policy ni VPPda faol/o'chiradi
func (rs *RuleScheduler) enableDisableABFOnVPP(ctx context.Context, policyID uint32, shouldBeActive bool) error {
	ruleID := fmt.Sprintf("%d", policyID)
	backup, backupExists := rs.vppClient.TimeGroupManager.GetDisabledRuleBackup("ABF", ruleID)

	// Agar ABF hozir faol bo'lishi kerak bo'lsa
	if shouldBeActive {
		// Agar backup mavjud bo'lsa (ya'ni avval o'chirilgan edi), uni qayta tiklash kerak
		if backupExists && !backup.LastActive {
			log.Printf("  🔄 ABF Policy %d ni qayta faollashtirish...\n", policyID)

			// Interface binding larni tiklash
			if bindings, ok := backup.Configuration["attachments"].([]interface{}); ok {
				for _, b := range bindings {
					if binding, ok := b.(map[string]interface{}); ok {
						swIfIndex, err := rs.asUint32(binding["sw_if_index"])
						if err != nil {
							log.Printf("  ⚠️ ABF binding sw_if_index xato: %v\n", err)
							continue
						}
						priority, err := rs.asUint32(binding["priority"])
						if err != nil {
							log.Printf("  ⚠️ ABF binding priority xato: %v\n", err)
							continue
						}
						isIPv6, err := rs.asBool(binding["is_ipv6"])
						if err != nil {
							log.Printf("  ⚠️ ABF binding is_ipv6 xato: %v\n", err)
							continue
						}

						// ABF ni interfaceiga qayta bog'lash
						if err := rs.vppClient.AbfManager.AttachToInterface(ctx, policyID, swIfIndex, priority, isIPv6, true); err != nil {
							log.Printf("  ⚠️ ABF %d ni interface %d ga bog'lashda xato: %v\n", policyID, swIfIndex, err)
						}
					}
				}
			}

			// Backup-ni o'chirish
			_ = rs.vppClient.TimeGroupManager.RemoveDisabledRuleBackup("ABF", ruleID)
			log.Printf("  ✅ ABF Policy %d muvaffaqiyatli qayta faollashtirildi\n", policyID)
		}
		return nil
	}

	// Agar ABF o'chirilishi kerak bo'lsa
	if !backupExists || backup.LastActive {
		log.Printf("  ⏸️ ABF Policy %d ni o'chirish (interfacelardan uzish)...\n", policyID)

		// Interface attachment larni saqlash
		attachments, err := rs.vppClient.AbfManager.ListInterfaceAttachments(ctx)
		if err != nil {
			return err
		}

		var attachmentList []interface{}
		for _, attach := range attachments {
			if attach.Attach.PolicyID == policyID {
				attachmentList = append(attachmentList, map[string]interface{}{
					"sw_if_index": uint32(attach.Attach.SwIfIndex),
					"priority":    attach.Attach.Priority,
					"is_ipv6":     attach.Attach.IsIPv6,
				})

				// Interface-dan ABF ni uzish
				err := rs.vppClient.AbfManager.AttachToInterface(ctx, policyID, uint32(attach.Attach.SwIfIndex),
					attach.Attach.Priority, attach.Attach.IsIPv6, false)
				if err != nil {
					log.Printf("  ⚠️ ABF %d ni interface %d dan uzishda xato: %v\n", policyID, attach.Attach.SwIfIndex, err)
				}
			}
		}

		// TimeGroup assignment ni topish
		timeGroups, _ := rs.vppClient.TimeGroupManager.GetRuleTimeAssignments(ctx, "ABF", ruleID)
		timeGroupID := ""
		if len(timeGroups) > 0 {
			timeGroupID = timeGroups[0].ID
		}

		// Backup-ni saqlash
		_ = rs.vppClient.TimeGroupManager.SaveDisabledRuleBackup(&time_group.DisabledRuleBackup{
			RuleType: "ABF",
			RuleID:   ruleID,
			Configuration: map[string]interface{}{
				"policy_id":   policyID,
				"attachments": attachmentList,
			},
			TimeGroupID: timeGroupID,
			LastActive:  false,
		})

		log.Printf("  ⛔ ABF Policy %d interfacelardan ajratildi\n", policyID)
	}

	return nil
}

func (rs *RuleScheduler) asUint32(v interface{}) (uint32, error) {
	switch t := v.(type) {
	case uint32:
		return t, nil
	case uint64:
		return uint32(t), nil
	case int:
		return uint32(t), nil
	case int32:
		return uint32(t), nil
	case int64:
		return uint32(t), nil
	case float32:
		return uint32(t), nil
	case float64:
		return uint32(t), nil
	default:
		return 0, fmt.Errorf("uint32 ga o'girish imkonsiz: %T", v)
	}
}

func (rs *RuleScheduler) asUint64(v interface{}) (uint64, error) {
	switch t := v.(type) {
	case uint64:
		return t, nil
	case uint32:
		return uint64(t), nil
	case int:
		return uint64(t), nil
	case int32:
		return uint64(t), nil
	case int64:
		return uint64(t), nil
	case float32:
		return uint64(t), nil
	case float64:
		return uint64(t), nil
	default:
		return 0, fmt.Errorf("uint64 ga o'girish imkonsiz: %T", v)
	}
}

func (rs *RuleScheduler) asBool(v interface{}) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	default:
		return false, fmt.Errorf("bool ga o'girish imkonsiz: %T", v)
	}
}

func (rs *RuleScheduler) asString(v interface{}) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	default:
		return "", fmt.Errorf("string ga o'girish imkonsiz: %T", v)
	}
}

// Helper functions for parsing backup configuration
func getStringFromMap(m map[string]interface{}, key, defaultVal string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func getUint8FromMap(m map[string]interface{}, key string) uint8 {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return uint8(t)
		case int:
			return uint8(t)
		case int64:
			return uint8(t)
		case uint8:
			return t
		}
	}
	return 0
}

func getUint16FromMap(m map[string]interface{}, key string) uint16 {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return uint16(t)
		case int:
			return uint16(t)
		case int64:
			return uint16(t)
		case uint16:
			return t
		}
	}
	return 0
}
