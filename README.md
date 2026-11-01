# 03_TUM_Quantum — Post-Quantum Cryptography & Quantum Research Lab
## บริษัทที่ 3 ในเครือ TUM Group Holdings Co., Ltd. (อนาคตของกลุ่ม TUM)

> **คำขวัญ:** *"Quantum Immunity, NIST FIPS Standards & Zero-Disruption Hybrid Migration"*  
> **สถานะ:** Active Research & Deep-Tech Lab 🟢  
> **ผู้รับผิดชอบหลัก:** Chief Quantum Scientist / Managing Director & Standards Liaison (NIST / NCSA)

---

## 1. ขอบเขตและหน้าที่ความรับผิดชอบ (Company Scope)

**TUMQuantum Co., Ltd.** คือบริษัทวิจัยและพัฒนานวัตกรรมวิทยาการรหัสลับขั้นสูง (Post-Quantum Cryptography - PQC) เพื่อปกป้องโครงสร้างพื้นฐานดิจิทัลล่วงหน้าก่อนภัยคอมพิวเตอร์ควอนตัม (Q-Day / Shor's Algorithm) จะมาถึง:

1. **NIST FIPS PQC Standard Implementations:**
   - **NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium):** ลายมือชื่อดิจิทัลแบบแลตทิซ (Lattice-based Digital Signature) ในระดับความปลอดภัย Category 2 (Dilithium-44), Category 3 (Dilithium-65), และ Category 5 (Dilithium-87)
   - **NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber):** กลไกการห่อหุ้มกุญแจรหัสลับ (Key Encapsulation Mechanism) ระดับ Category 1 (512), Category 3 (768), Category 5 (1024)
2. **ปรัชญา "ไม่ทอดทิ้งใครไว้ข้างหลัง" (Hybrid Migration Adapter):**
   - พัฒนา Dual-Envelope Hybrid Signatures รวมพลังระหว่างรหัสลับดั้งเดิม (RSA / ECDSA) กับ PQC (ML-DSA)
   - ช่วยให้ระบบของลูกค้าสามารถทยอยเปลี่ยนผ่านสู่ยุคควอนตัมได้แบบค่อยเป็นค่อยไป โดยไม่ต้องรื้อถอนระบบเก่า
3. **Quantum Vulnerability Auditing & Attack Simulation (HNDL):**
   - แซนด์บ็อกซ์จำลองการโจมตีควอนตัมแบบ **Harvest Now, Decrypt Later (HNDL)** ตามมาตรฐาน NIST & IETF draft-ietf-lamps-pq-composite-sigs
   - จำลองการถอดรหัสลับด้วย Shor's Algorithm (IFP / ECDLP) และ Grover's Algorithm
   - บริการตรวจสอบความพร้อมสู่ยุคควอนตัม (Quantum Readiness Audit & Batch Asset Scorecard)
4. **Sovereign Post-Quantum Identity Assertion Tokens:**
   - การออกและตรวจสอบโทเคนอัตลักษณ์ PQC-JWT แบบ Dual-Signed เพื่อปกป้องบัตรประชาชนดิจิทัล พาสปอร์ต และข้อมูลราชการ

---

## 2. โครงสร้างโฟลเดอร์ภายใน (Internal Architecture)

```
tum-quantum/
├── Core/
│   ├── Interfaces/
│   │   ├── IQuantumSafeTrustEngine.cs       # เอนจินแลตทิซ NIST FIPS 203/204
│   │   ├── IHybridMigrationAdapter.cs       # อะแดปเตอร์ย้ายผ่านระบบเดิม (SCRUM-18)
│   │   ├── IPqcAssertionSigner.cs           # โทเคนยืนยันอัตลักษณ์ PQC (SCRUM-25)
│   │   └── IHndlQuantumAttackSimulator.cs   # แซนด์บ็อกซ์จำลองภัย HNDL (SCRUM-35)
│   └── Models/                              # แบบจำลองข้อมูลและเมตริกความปลอดภัย
│       ├── HndlSimulationProfile.cs         # โพรไฟล์ฮาร์ดแวร์ควอนตัม CRQC/NISQ
│       ├── HndlSimulationRequest.cs         # คำขอจำลองการโจมตี HNDL
│       ├── HndlSimulationResult.cs          # ผลการประเมินและสถานะ Forward Secrecy
│       ├── HndlHarvestBatch.cs              # การประเมินชุดสินทรัพย์รหัสลับระดับองค์กร
│       ├── QuantumCryptanalysisMetrics.cs   # สูตรคำนวณ Qubits และ Circuit Depth
│       ├── PqcKeyPair.cs & PqcSignatureAlgorithm.cs
│       └── HybridDualEnvelope.cs & PqcIdentityAssertion.cs
├── Engine/
│   ├── QuantumSafeTrustEngine.cs            # เครื่องยนต์ตรวจสอบแลตทิซ FIPS 203/204
│   ├── HybridPermissiveMigrationAdapter.cs  # อะแดปเตอร์ย้ายผ่าน Dual-Envelope
│   ├── PqcAssertionSigner.cs                # ตัวลงนามและตรวจสอบโทเคน PQC-JWT
│   └── HndlQuantumAttackSimulator.cs        # แซนด์บ็อกซ์จำลองการโจมตี HNDL Shor/Grover
├── Server/
│   └── Program.cs                           # Microservice ASP.NET Core 8 REST API
├── Tests/                                   # ชุดทดสอบ xUnit ผ่าน 64/64 ข้อ (100% PASS)
│   ├── QuantumSafeTrustTests.cs
│   ├── HybridPermissiveMigrationAdapterTests.cs
│   ├── PqcAssertionSignerTests.cs
│   └── HndlQuantumAttackSimulatorTests.cs
├── Tum.Quantum.csproj                       # Multi-Targeting (.NET 5.0, .NET 8.0, .NET 10.0)
└── README.md                                # เอกสารภาพรวมบริษัท TUMQuantum
```

---

## 3. REST API Endpoints (Microservice Server)

| Method | Endpoint | รายละเอียด |
| :--- | :--- | :--- |
| `GET` | `/health` | ตรวจสอบสถานะการทำงานและขีดความสามารถ PQC |
| `GET` | `/api/pqc/status` | รายการอัลกอริทึมที่พร้อมให้บริการและสถานะความสอดคล้อง NIST FIPS |
| `POST` | `/api/pqc/hndl/simulate` | จำลองการโจมตีควอนตัมแบบ HNDL ต่อข้อมูลที่ถูกดักจับ |
| `POST` | `/api/pqc/hndl/batch` | ประเมินความพร้อมสู่ยุคควอนตัมของกองทัพสินทรัพย์ดิจิทัล (Fleet Scorecard) |
| `GET` | `/api/pqc/hndl/complexity` | ดึงค่าเมตริกทางทฤษฎี (จำนวน Logical/Physical Qubits, Gate Depth) |

---

## 4. ความเชื่อมโยงกับบริษัทย่อยอื่น (Synergy & Cross-Company Links)

- ➡️ **ส่งมอบให้ `01_TUM_Trust_Security`:** ไลบรารีตรวจสอบลายมือชื่อควอนตัมสำหรับปกป้องข้อมูลหนังสือเดินทางและบัตรประชาชน
- ➡️ **ส่งมอบให้ `02_TUM_Socs`:** อัลกอริทึม Merkle Tree และ Hash Chaining ทนควอนตัมเพื่อป้องกันการแก้ไขบันทึกย้อนหลัง
- ➡️ **ส่งมอบให้ `tum-central-director`:** บริการตรวจประเมินความเสี่ยงควอนตัม HNDL ผ่าน REST API
- ⬅️ **รับข้อมูลจากทั้งสองบริษัท:** สถิติทราฟฟิกและข้อมูลอัตลักษณ์เพื่อใช้ทำ Quantum Attack Simulation
