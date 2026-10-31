# 03_TUM_Quantum — Post-Quantum Cryptography & Quantum Research Lab
## บริษัทที่ 3 ในเครือ TUM Group Holdings Co., Ltd. (อนาคตของกลุ่ม TUM)

> **คำขวัญ:** *"Quantum Immunity, NIST FIPS Standards & Zero-Disruption Hybrid Migration"*  
> **สถานะ:** Active Research & Deep-Tech Lab 🟢  
> **ผู้รับผิดชอบหลัก:** Chief Quantum Scientist / Managing Director & Standards Liaison (NIST / NCSA)

---

## 1. ขอบเขตและหน้าที่ความรับผิดชอบ (Company Scope)

**TUMQuantum Co., Ltd.** คือบริษัทวิจัยและพัฒนานวัตกรรมวิทยาการรหัสลับขั้นสูง (Post-Quantum Cryptography - PQC) เพื่อปกป้องโครงสร้างพื้นฐานดิจิทัลล่วงหน้าก่อนภัยคอมพิวเตอร์ควอนตัม (Q-Day / Shor's Algorithm) จะมาถึง:

1. **NIST FIPS PQC Standard Implementations:**
   - **NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium):** ลายมือชื่อดิจิทัลแบบแลตทิซ (Lattice-based Digital Signature) ในระดับความปลอดภัย Category 2 (Dilithium-44) และ Category 3 (Dilithium-65)
   - **NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber):** กลไกการห่อหุ้มกุญแจรหัสลับ (Key Encapsulation Mechanism)
2. **ปรัชญา "ไม่ทอดทิ้งใครไว้ข้างหลัง" (Hybrid Migration Adapter):**
   - พัฒนา Dual-Envelope Hybrid Signatures รวมพลังระหว่างรหัสลับดั้งเดิม (RSA / ECDSA) กับ PQC (ML-DSA)
   - ช่วยให้ระบบของลูกค้าสามารถทยอยเปลี่ยนผ่านสู่ยุคควอนตัมได้แบบค่อยเป็นค่อยไป โดยไม่ต้องรื้อถอนระบบเก่า
3. **Quantum Vulnerability Auditing & Attack Simulation:**
   - ตรวจจับอัลกอริทึมที่มีความเสี่ยงต่อการถูกเจาะด้วยคอมพิวเตอร์ควอนตัม (Harvest Now, Decrypt Later - HNDL)
   - บริการตรวจสอบความพร้อมสู่ยุคควอนตัม (Quantum Readiness Audit)

---

## 2. โครงสร้างโฟลเดอร์ภายใน (Internal Architecture)

```
03_TUM_Quantum/
├── Core/
│   ├── Interfaces/             # IQuantumSafeTrustEngine
│   └── Models/                 # PqcKeyPair, PqcSignatureAlgorithm, PqcVerificationResult
├── Engine/
│   └── QuantumSafeTrustEngine.cs # เครื่องยนต์ตรวจสอบแลตทิซ ML-DSA และ Dual-Envelope
├── docs/                        # เอกสารงานวิจัยควอนตัมและการย้ายผ่านระบบ
├── Tum.Quantum.csproj          # โปรเจกต์ไลบรารีควอนตัม (.NET 5.0, .NET 8.0, .NET 10.0)
└── README.md                    # เอกสารภาพรวมบริษัท TUMQuantum
```

---

## 3. ความเชื่อมโยงกับบริษัทย่อยอื่น (Synergy & Cross-Company Links)

- ➡️ **ส่งมอบให้ `01_TUM_Trust_Security`:** ไลบรารีตรวจสอบลายมือชื่อควอนตัมสำหรับปกป้องข้อมูลหนังสือเดินทางและบัตรประชาชน
- ➡️ **ส่งมอบให้ `02_TUM_Socs`:** อัลกอริทึม Merkle Tree และ Hash Chaining ทนควอนตัมเพื่อป้องกันการแก้ไขบันทึกย้อนหลัง
- ⬅️ **รับข้อมูลจากทั้งสองบริษัท:** สถิติทราฟฟิกและข้อมูลอัตลักษณ์เพื่อใช้ทำ Quantum Attack Simulation
