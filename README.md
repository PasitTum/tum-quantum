# 03_TUM_Quantum — Post-Quantum Cryptography & Quantum Research Lab
## บริษัทที่ 3 ในเครือ TUM Group Holdings Co., Ltd. (อนาคตของกลุ่ม TUM)

> **คำขวัญ:** *"Quantum Immunity, NIST FIPS Standards & Zero-Disruption Hybrid Migration"*  
> **สถานะ:** Active Research & Deep-Tech Lab 🟢 (Sprints 1 – 15 เสร็จสิ้นสมบูรณ์ + Turnkey Gateway & Constant-Time Suite)  
> **ผู้รับผิดชอบหลัก:** Chief Quantum Scientist / Managing Director & Standards Liaison (NIST / NCSA)

---

## 1. ขอบเขตและหน้าที่ความรับผิดชอบ (Company Scope)

**TUMQuantum Co., Ltd.** คือบริษัทวิจัยและพัฒนานวัตกรรมวิทยาการรหัสลับขั้นสูง (Post-Quantum Cryptography - PQC) เพื่อปกป้องโครงสร้างพื้นฐานดิจิทัลล่วงหน้าก่อนภัยคอมพิวเตอร์ควอนตัม (Q-Day / Shor's Algorithm) จะมาถึง:

1. **NIST FIPS PQC Standard Implementations:**
   - **NIST FIPS 204 (ML-DSA / CRYSTALS-Dilithium):** ลายมือชื่อดิจิทัลแบบแลตทิซในระดับความปลอดภัย Category 2 (44), Category 3 (65), และ Category 5 (87)
   - **NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber):** กลไกการห่อหุ้มกุญแจรหัสลับ Category 1 (512), Category 3 (768), Category 5 (1024)
2. **Turnkey Product: TUM-Quantum Reverse Proxy Gateway:**
   - วางคั่นหน้า Web Server เดิม (Microsoft IIS, Nginx, Apache HTTPD) เพื่อทำ Edge Post-Quantum TLS 1.3 Termination (`X25519MLKEM768`)
   - ฉีดส่วนหัวความปลอดภัยควอนตัม (`X-Quantum-Safe: true`, `X-PQC-Key-Exchange: x25519_mlkem768`) โดยระบบเดิมไม่ต้องแก้โค้ดแม้แต่บรรทัดเดียว
3. **Constant-Time & Timing Attack Vulnerability Analysis (DudeCT):**
   - ชุดทดสอบทางสถิติ Welch's two-sample t-test ($|t| < 4.5$) พิสูจน์ความคงที่ของเวลาการประมวลผล ไร้การรั่วไหลผ่าน Side-Channel
4. **ปรัชญา "ไม่ทอดทิ้งใครไว้ข้างหลัง" (Hybrid Migration Adapter):**
   - พัฒนา Dual-Envelope Hybrid Signatures รวมพลังระหว่างรหัสลับดั้งเดิม (RSA / ECDSA) กับ PQC (ML-DSA) (SCRUM-18)
5. **Quantum Vulnerability Auditing & Attack Simulation (HNDL):**
   - แซนด์บ็อกซ์จำลองการโจมตีควอนตัมแบบ **Harvest Now, Decrypt Later (HNDL)** (SCRUM-35)
6. **Post-Quantum Network & Identity Infrastructure (Sprints 10 – 15):**
   - **Post-Quantum TLS 1.3 Handshake Engine:** Hybrid X25519MLKEM768 Key Encapsulation (Sprint 10)
   - **Zero-Knowledge Proof (zk-SNARKs) Attribute Prover:** พิสูจน์อายุ/สถานะทางการเงินโดยไม่เปิดเผย PII (Sprint 11)
   - **OASIS PKCS#11 Quantum Hardware HSM Driver:** ป้องกันคีย์รั่วไหลออกจากฮาร์ดแวร์ 100% (Sprint 12)
   - **NIST FIPS 140-3 Readiness Audit Suite:** การตรวจรับรองโมดูลรหัสลับระดับ 1 ถึง 4 (Sprint 13)
   - **RFC 3161 Post-Quantum Time-Stamp Authority (PQC-TSA):** ประทับเวลารับรองตาม พ.ร.บ.ธุรกรรมฯ (Sprint 14)
   - **Quantum-Safe OpenID Connect (PQC-OIDC):** ออกและตรวจสอบ ID Tokens ด้วย ML-DSA-65 (Sprint 15)

---

## 2. โครงสร้างโฟลเดอร์ภายใน (Internal Architecture)

```
tum-quantum/
├── Core/
│   ├── Interfaces/
│   │   ├── IQuantumSafeTrustEngine.cs       # เอนจินแลตทิซ NIST FIPS 203/204
│   │   ├── IConstantTimeAnalyzer.cs         # ตัววิเคราะห์ Side-Channel DudeCT
│   │   ├── IHybridMigrationAdapter.cs       # อะแดปเตอร์ย้ายผ่านระบบเดิม (SCRUM-18)
│   │   ├── IPqcAssertionSigner.cs           # โทเคนยืนยันอัตลักษณ์ PQC (SCRUM-25)
│   │   ├── IHndlQuantumAttackSimulator.cs   # แซนด์บ็อกซ์จำลองภัย HNDL (SCRUM-35)
│   │   ├── IPqcTls13HandshakeEngine.cs      # Handshake TLS 1.3 ML-KEM-768 (Sprint 10)
│   │   ├── IPqcZeroKnowledgeProver.cs       # เครื่องยนต์ Zero-Knowledge Proof (Sprint 11)
│   │   ├── IPkcs11QuantumHsmDriver.cs       # ไดรเวอร์ PKCS#11 Quantum HSM (Sprint 12)
│   │   ├── IFips140AuditRunner.cs           # ตัวตรวจรับรอง FIPS 140-3 Levels 1-4 (Sprint 13)
│   │   ├── ITimeStampAuthorityEngine.cs     # เซิร์ฟเวอร์ RFC 3161 PQC-TSA (Sprint 14)
│   │   └── IPqcOidcTokenEngine.cs           # ระบบออกและตรวจโทเคน PQC-OIDC (Sprint 15)
│   └── Models/                              # แบบจำลองข้อมูลและเมตริกความปลอดภัย
│       ├── ConstantTimeAnalysisModels.cs    # โมเดล DudeCT และ Side-Channel Report
│       ├── HndlSimulationProfile.cs & HndlSimulationRequest.cs & HndlSimulationResult.cs
│       ├── PqcTls13Models.cs & PqcZkModels.cs & Pkcs11HsmModels.cs
│       ├── Fips140AuditModels.cs & TimeStampAuthorityModels.cs & PqcOidcModels.cs
│       └── PqcKeyPair.cs & HybridDualEnvelope.cs & PqcIdentityAssertion.cs
├── Engine/
│   ├── QuantumSafeTrustEngine.cs            # เครื่องยนต์ตรวจสอบแลตทิซ FIPS 203/204 (Constant-Time Hardened)
│   ├── ConstantTimeAnalyzer.cs              # เครื่องมือวัดสถิติ DudeCT Welch's t-test
│   ├── HybridPermissiveMigrationAdapter.cs  # อะแดปเตอร์ย้ายผ่าน Dual-Envelope
│   ├── PqcAssertionSigner.cs                # ตัวลงนามและตรวจสอบโทเคน PQC-JWT
│   ├── HndlQuantumAttackSimulator.cs        # แซนด์บ็อกซ์จำลองการโจมตี HNDL Shor/Grover
│   ├── PqcTls13HandshakeEngine.cs           # เอนจิน TLS 1.3 Key Schedule (RFC 8446)
│   ├── PqcZeroKnowledgeProver.cs            # ตัวพิสูจน์ NIZK บนโครงตาข่าย M-LWE/SIS
│   ├── Pkcs11QuantumHsmDriver.cs            # ไดรเวอร์อุปกรณ์ฮาร์ดแวร์ Quantum HSM
│   ├── Fips140AuditRunner.cs                # ตัวตรวจรับรอง FIPS 140-3 พร้อม Known Answer Tests
│   ├── TimeStampAuthorityEngine.cs          # เซิร์ฟเวอร์ประทับเวลารับรองตาม RFC 3161
│   └── PqcOidcTokenEngine.cs                # เครื่องยนต์ PQC OpenID Connect
├── Server/
│   └── Program.cs                           # Microservice ASP.NET Core 8 REST API
├── gateway/                                 # 🚀 Turnkey Product: TUM-Quantum Reverse Proxy Gateway
│   ├── Dockerfile                           # OQS Nginx Container Image with ML-KEM & ML-DSA
│   ├── nginx.conf                           # คอนฟิก TLS 1.3 PQC Termination & Header Injection
│   ├── docker-entrypoint.sh                 # สคริปต์ตรวจสอบและสตาร์ทเกตเวย์
│   ├── generate-pqc-certs.sh                # ตัวสร้างใบรับรองลูกผสมและ PQC X.509
│   ├── test-gateway.sh / test-gateway.ps1   # ชุดทดสอบเกตเวย์อัตโนมัติ
│   └── mock-upstream/                       # ตัวอย่างเซิร์ฟเวอร์เดิมหลังบ้าน (Legacy App)
├── docker-compose.yml                       # Turnkey Stack: Gateway + Engine + Upstream
├── Tests/                                   # ชุดทดสอบ xUnit ผ่าน 101/101 ข้อ (100% PASS)
├── docs/                                    # เอกสารสถาปัตยกรรมและงานวิจัย
│   ├── QUANTUM_READINESS_ENTERPRISE_BRIEFING.md  # คู่มือสถาปัตยกรรม Enterprise Briefing
│   ├── QUANTUM_READINESS_ENTERPRISE_BRIEFING.pdf # เอกสารฉบับพิมพ์สมบูรณ์สำหรับผู้บริหาร (Executive PDF)
│   └── QUANTUM_RESEARCH_AND_FRONTIER_ROADMAP.md # รายงานวิจัยคณิตศาสตร์แลตทิซขั้นสูง
├── Tum.Quantum.csproj                       # Multi-Targeting (.NET 5.0, .NET 8.0, .NET 10.0)
└── README.md                                # เอกสารภาพรวมบริษัท TUMQuantum
```

---

## 3. REST API Endpoints (Microservice Server)

| Method | Endpoint | รายละเอียด |
| :--- | :--- | :--- |
| `GET` | `/health` | ตรวจสอบสถานะการทำงานและรายการขีดความสามารถ PQC (Sprints 1-15 + DudeCT) |
| `GET` | `/api/pqc/status` | รายการอัลกอริทึมและสถานะความสอดคล้อง NIST FIPS |
| `POST` | `/api/pqc/audit/timing-attack` | รันการตรวจวิเคราะห์ความคงที่ของเวลา (DudeCT Constant-Time Analysis) |
| `POST` | `/api/pqc/hndl/simulate` | จำลองการโจมตีควอนตัมแบบ HNDL ต่อข้อมูลที่ถูกดักจับ |
| `POST` | `/api/pqc/hndl/batch` | ประเมินความพร้อมสู่ยุคควอนตัมของกองทัพสินทรัพย์ดิจิทัล (Fleet Scorecard) |
| `GET` | `/api/pqc/hndl/complexity` | ดึงค่าเมตริกทางทฤษฎี (จำนวน Logical/Physical Qubits, Gate Depth) |
| `POST` | `/api/pqc/tls/client-hello` | สร้าง ClientHello สำหรับ Post-Quantum TLS 1.3 Handshake |
| `POST` | `/api/pqc/tls/process-hello` | ประมวลผลและสร้าง ServerHello พร้อม Encapsulated Key Share |
| `POST` | `/api/pqc/zkp/age-proof` | สร้างหลักฐาน Zero-Knowledge ยืนยันอายุตามเกณฑ์โดยไม่เปิดเผยวันเกิด |
| `POST` | `/api/pqc/zkp/verify` | ตรวจสอบความถูกต้องของหลักฐาน Zero-Knowledge |
| `GET` | `/api/pqc/hsm/info` | สอบถามสถานะและขีดความสามารถของ Quantum HSM ผ่าน PKCS#11 |
| `POST` | `/api/pqc/audit/fips140` | รันชุดตรวจสอบความพร้อมตามมาตรฐาน NIST FIPS 140-3 Levels 1-4 |
| `POST` | `/api/pqc/tsa/issue` | ออกใบรับรองประทับเวลา Post-Quantum ตามมาตรฐาน RFC 3161 |
| `POST` | `/api/pqc/oidc/token` | ออกโทเคน Post-Quantum OIDC ID Token ลงนามด้วย ML-DSA-65 |
| `POST` | `/api/pqc/oidc/validate` | ตรวจสอบความถูกต้องและลายมือชื่อของ PQC-OIDC Token |
| `GET` | `/.well-known/jwks.json` | เผยแพร่กุญแจสาธารณะ PQC-JWKS สำหรับการตรวจสอบภายนอก |

---

## 4. วิธีการเปิดใช้งาน Turnkey Product (Quick Start)

```bash
# สั่งรันทั้งระบบด้วย Docker Compose
docker compose up -d --build

# ตรวจสอบการทำงานของ Gateway และการฉีดส่วนหัว
powershell -ExecutionPolicy Bypass -File gateway\test-gateway.ps1
```

อ่านเอกสารสรุปสถาปัตยกรรมสำหรับผู้บริหารองค์กรได้ที่ [**`docs/QUANTUM_READINESS_ENTERPRISE_BRIEFING.md`**](file:///D:/TUM/tum-quantum/docs/QUANTUM_READINESS_ENTERPRISE_BRIEFING.md) และเอกสารฉบับพิมพ์ [**`docs/QUANTUM_READINESS_ENTERPRISE_BRIEFING.pdf`**](file:///D:/TUM/tum-quantum/docs/QUANTUM_READINESS_ENTERPRISE_BRIEFING.pdf)
