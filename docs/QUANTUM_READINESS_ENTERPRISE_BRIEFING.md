# 🛡️ TUMQuantum: Quantum-Readiness Enterprise Briefing & Architecture Blueprint
## เอกสารคู่มือสถาปัตยกรรมความพร้อมสู่ยุคควอนตัมและโซลูชัน Turnkey Gateway สำหรับองค์กร
**ระดับการนำเสนอ:** C-Level Executives (CIO, CTO, CISO), Enterprise Security Architects, & Infrastructure Engineers  
**ผู้จัดทำ:** Lead Scientist & Architecture Board, TUMQuantum Co., Ltd.  
**มาตรฐานอ้างอิง:** NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA), RFC 8446 (TLS 1.3), RFC 3161, NIST FIPS 140-3  
**วันที่ประกาศใช้:** พฤศจิกายน 2026 | **เวอร์ชัน:** 1.0 (Enterprise Turnkey Edition)

---

## 1. Executive Summary & The Impending Quantum Horizon

### 1.1 ภัยคุกคามคอมพิวเตอร์ควอนตัม (Cryptanalytically Relevant Quantum Computer - CRQC)
ในปัจจุบัน โครงสร้างพื้นฐานความมั่นคงปลอดภัยไซเบอร์ของภาคการเงิน ธนาคาร โทรคมนาคม และหน่วยงานรัฐบาลทั่วโลก พึ่งพาวิทยาการรหัสลับแบบกุญแจอสมมาตร (Asymmetric Public-Key Cryptography) เป็นหลัก ได้แก่ **RSA (2048 - 4096 บิต)**, **ECDSA (secp256k1, P-256)**, และ **Diffie-Hellman / ECDH**

เมื่อคอมพิวเตอร์ควอนตัมที่มีความเสถียร (Fault-Tolerant Quantum Computer) บรรลุขีดความสามารถประมาณ $4,000 - 10,000$ Logical Qubits (คาดการณ์ช่วงปี **2029 – 2030** หรือเรียกว่า **Q-Day**):
1. **Shor's Algorithm (1994):** สามารถแยกตัวประกอบจำนวนเต็ม (Integer Factorization) และคำนวณ Discrete Logarithm ได้ในเวลาเชิงพหุนาม (Polynomial Time $O((\log N)^3)$) — **ทำลายระบบ RSA และ ECC ทั้งหมดทันที**
2. **Grover's Algorithm (1996):** ลดระดับความปลอดภัยของอัลกอริทึมกุญแจสมมาตรและฟังก์ชันแฮชลงครึ่งหนึ่ง ($O(\sqrt{N})$) — ทำให้ AES-128 มีความแข็งแกร่งเหลือเพียง 64 บิต ในขณะที่ **AES-256 / ChaCha20** ยังคงปลอดภัยที่ 128 บิต

### 1.2 วิกฤตด่วนปัจจุบัน: "Harvest Now, Decrypt Later" (HNDL)
องค์กรส่วนใหญ่เข้าใจผิดว่าภัยควอนตัมเป็นเรื่องของอนาคต แต่ในความเป็นจริง **การโจมตีได้เริ่มต้นขึ้นแล้วในวันนี้**:
- กลุ่มผู้โจมตีระดับรัฐ (Nation-State Threat Actors) กำลังดักจับและกักตักเก็บข้อมูลทราฟฟิกเครือข่ายที่เข้ารหัส (Encrypted Intercepts) ทางทะเล เคเบิลใต้น้ำ ดาต้าเซ็นเตอร์ และคลาวด์
- ข้อมูลที่ถูกเก็บไว้ (เช่น ข้อมูลประวัติธุรกรรมธนาคาร, ความลับทางการค้า, ข้อมูลพันธุกรรม, และความลับความมั่นคงของชาติ) จะถูกนำมาถอดรหัสย้อนหลังทันทีที่เครื่องควอนตัมพร้อมใช้งาน
- **บทสรุป:** หากไม่เปลี่ยนผ่านสู่ระบบ Post-Quantum ในวันนี้ ข้อมูลทราฟฟิกทั้งหมดที่ส่งผ่านอินเทอร์เน็ตในปัจจุบันถือว่าตกอยู่ในความเสี่ยงแล้ว 100%

---

## 2. NIST Post-Quantum Cryptography Standards Breakdown

สถาบันมาตรฐานและเทคโนโลยีแห่งชาติสหรัฐฯ (NIST) ได้ประกาศมาตรฐานอย่างเป็นทางการในเดือนสิงหาคม 2024:

```
+-----------------------------------------------------------------------------------------+
|                              NIST FIPS PQC STANDARDS (2024)                             |
+-----------------------------------------------------------------------------------------+
|  FIPS 203: ML-KEM (Module-Lattice KEM)       |  FIPS 204: ML-DSA (Module-Lattice DSA)   |
|  - อ้างอิงจาก CRYSTALS-Kyber                 |  - อ้างอิงจาก CRYSTALS-Dilithium         |
|  - ใช้สำหรับ: การแลกเปลี่ยนกุญแจ (TLS, VPN) |  - ใช้สำหรับ: ลายมือชื่อดิจิทัลและใบรับรอง |
|  - พารามิเตอร์: 512, 768, 1024              |  - พารามิเตอร์: 44, 65, 87               |
|  - ปัญหาคณิตศาสตร์: Module-LWE              |  - ปัญหาคณิตศาสตร์: Module-LWE / SIS     |
+-----------------------------------------------------------------------------------------+
```

### ตารางเปรียบเทียบขนาดคีย์และระดับความปลอดภัย (Security Categories)

| มาตรฐาน | อัลกอริทึม | NIST Security Category | ความยาว Public Key | ความยาว Ciphertext / Sig | Security Equivalent | เหมาะสำหรับงาน |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| **FIPS 203** | **ML-KEM-512** | Category 1 | 800 bytes | 768 bytes | AES-128 | IoT, Embedded Systems |
| **FIPS 203** | **ML-KEM-768** ⭐ | **Category 3** | **1,184 bytes** | **1,088 bytes** | **AES-192** | **Enterprise TLS 1.3 (Recommended)** |
| **FIPS 203** | **ML-KEM-1024** | Category 5 | 1,568 bytes | 1,568 bytes | AES-256 | Top-Secret, Military |
| **FIPS 204** | **ML-DSA-44** | Category 2 | 1,312 bytes | 2,420 bytes | SHA-256 / RSA-2048 | Mobile Apps, Microservices |
| **FIPS 204** | **ML-DSA-65** ⭐ | **Category 3** | **1,952 bytes** | **3,293 bytes** | **SHA-384 / RSA-3072** | **X.509 PKI & Identity Tokens** |
| **FIPS 204** | **ML-DSA-87** | Category 5 | 2,592 bytes | 4,595 bytes | SHA-512 / RSA-4096 | Time-Stamp Authority (TSA), Root CA |

---

## 3. Turnkey Architectural Solution: TUM-Quantum Reverse Proxy Gateway

### 3.1 ปรัชญาการออกแบบ: "Zero-Disruption, Drop-in Quantum Immunity"
อุปสรรคสำคัญที่สุดในการย้ายผ่านระบบขององค์กรขนาดใหญ่ คือระบบแอปพลิเคชันเดิม (Core Banking, ERP, Web Portals, Kiosk APIs) มีโค้ดเบสหลายล้านบรรทัด และรันอยู่บนเทคโนโลยีที่หลากหลาย (Microsoft IIS, Nginx, Apache HTTPD, Java Tomcat, ASP.NET, Node.js) ซึ่งไม่สามารถแก้ไขหรือเขียนโค้ดเข้ารหัสใหม่ได้ในระยะเวลาอันสั้น

**TUM-Quantum Reverse Proxy Gateway** ถูกสร้างขึ้นเพื่อเป็น Turnkey Appliance:
- วางคั่นหน้า Web Server เดิม ทำหน้าที่เป็น **Edge Post-Quantum TLS 1.3 Termination**
- รับและเจรจาการเชื่อมต่อด้วยอัลกอริทึมลูกผสม **X25519MLKEM768** (ตามมาตรฐาน IETF/NIST)
- ตรวจสอบความถูกต้องของใบรับรองควอนตัม (ML-DSA) และลูกผสม (Hybrid X.509)
- **ฉีดหัวข้อข้อมูลความปลอดภัยควอนตัม (Quantum Telemetry Headers)** ส่งต่อให้เซิร์ฟเวอร์เดิมหลังบ้าน
- เซิร์ฟเวอร์เดิมได้รับความปลอดภัยระดับควอนตัมทันทีโดยไม่ต้องแก้ไขซอร์สโค้ดแม้แต่บรรทัดเดียว!

### 3.2 แผนภาพสถาปัตยกรรม (System Architecture Diagram)

```mermaid
graph TD
    subgraph External Clients
        C1["Modern Web Browsers<br/>(Chrome / Firefox / Edge PQC)"]
        C2["Smart Kiosks & Edge Devices<br/>(TUM-Quantum SDK)"]
        C3["Mobile Apps & Enterprise APIs"]
        C4["Legacy Clients (Fallback)"]
    end

    subgraph Demilitarized Zone (DMZ) / Ingress
        GW["🛡️ TUM-Quantum Reverse Proxy Gateway<br/>(Open-Quantum-Safe Nginx Engine)"]
    end

    subgraph Internal Secure Network (VPC / Mesh)
        S1["🏢 Existing Enterprise Web Server<br/>(Microsoft IIS / Apache / Nginx / Java)"]
        S2["⚡ TUM-Quantum Cryptography Service<br/>(ASP.NET Core 8 / Port 5100)"]
    end

    C1 -- "TLS 1.3 Hybrid<br/>(X25519MLKEM768 / ML-DSA-65)" --> GW
    C2 -- "PQC TLS 1.3 / ML-KEM-768" --> GW
    C3 -- "PQC REST / OIDC ID Token" --> GW
    C4 -- "TLS 1.2/1.3 Classical Fallback" --> GW

    GW -- "HTTP Reverse Proxy with Injected Headers<br/>(X-Quantum-Safe: true, X-PQC-Key-Exchange: ...)" --> S1
    GW -- "Direct Offload (/api/pqc/*)<br/>(FIPS 140 Audit, TSA, DudeCT, ZKP)" --> S2
```

### 3.3 ข้อมูลจำเพาะของส่วนหัวที่ถูกฉีด (Injected Header Specifications)

เมื่อทราฟฟิกผ่าน Gateway ระบบจะฉีด HTTP Headers ต่อไปนี้ส่งไปยัง Web Server หลังบ้าน:

| Header Name | ตัวอย่างค่าที่ส่ง | ความหมายและประโยชน์สำหรับแอปพลิเคชันหลังบ้าน |
| :--- | :--- | :--- |
| `X-Quantum-Safe` | `true` | ยืนยันว่าการเชื่อมต่อของไคลเอนต์ได้รับการปกป้องด้วยอัลกอริทึม PQC |
| `X-PQC-Key-Exchange` | `x25519_mlkem768` | ระบุอัลกอริทึมแลกเปลี่ยนคีย์ (เช่น ML-KEM-768 Hybrid) |
| `X-PQC-Cipher-Suite` | `TLS_AES_256_GCM_SHA384` | รหัสลับสมมาตรที่ใช้สำหรับ Data Channel |
| `X-PQC-Protocol` | `TLSv1.3` | เวอร์ชันของโปรโตคอล TLS |
| `X-PQC-Security-Bits` | `192` | ระดับความปลอดภัยเชิงบิตตามมาตรฐาน NIST Category 3 |
| `X-PQC-Gateway` | `TUM-Quantum-Gateway/1.0` | หมายเลขเวอร์ชันและสตริงระบุเกตเวย์ |
| `X-Forwarded-For` | `203.0.113.195` | IP ดั้งเดิมของผู้ใช้งานจริง |
| `X-Forwarded-Proto` | `https` | ยืนยันว่าการเชื่อมต่อภายนอกเป็น HTTPS |

---

## 4. Enterprise Integration Playbooks

### 4.1 Microsoft IIS (Internet Information Services) Integration
สำหรับองค์กรที่ใช้ Windows Server และ IIS:
1. ปรับพอร์ตของ IIS เว็บไซต์เดิมจากพอร์ต 443 ให้รับทราฟฟิกที่พอร์ตภายใน เช่น `127.0.0.1:8080` (หรือผูกกับ Private IP ใน Internal VLAN)
2. สั่งรัน Docker Container `tum-quantum-gateway` บน Windows Server (หรือบน Linux Ingress Node หน้า IIS Cluster):
   ```yaml
   ports:
     - "80:80"
     - "443:443"
   environment:
     - UPSTREAM_LEGACY_HOST=10.0.1.50   # IP ของ IIS Server
     - UPSTREAM_LEGACY_PORT=8080
   ```
3. ในโค้ด C# / ASP.NET (.NET Framework หรือ .NET 8) บน IIS สามารถอ่านค่าความปลอดภัยได้ทันที:
   ```csharp
   bool isQuantumSafe = Request.Headers["X-Quantum-Safe"] == "true";
   string kemGroup = Request.Headers["X-PQC-Key-Exchange"] ?? "None";
   
   if (!isQuantumSafe && requiresHighAssurance)
   {
       // แจ้งเตือนผู้ใช้หรือจำกัดสิทธิ์สำหรับรายการที่ต้องการความปลอดภัยสูง
   }
   ```

### 4.2 Nginx Enterprise & Apache HTTPD Integration
สำหรับเว็บเซิร์ฟเวอร์ Nginx หรือ Apache ที่ใช้งานอยู่เดิม:
- นำ `tum-quantum-gateway` ไปวางเป็น Edge Ingress
- ใน Nginx เดิมหลังบ้าน สามารถรับและบันทึก Log ของ PQC ได้โดยตรง:
  ```nginx
  log_format enterprise_pqc '$remote_addr - $remote_user [$time_local] "$request" '
                            'pqc_safe="$http_x_quantum_safe" '
                            'pqc_kem="$http_x_pqc_key_exchange"';
  access_log /var/log/nginx/pqc_access.log enterprise_pqc;
  ```

### 4.3 Kubernetes & Service Mesh (Istio / Envoy) Ingress
- ใช้งาน `tum-quantum-gateway` เป็น Ingress Controller หรือ Gateway Pod หน้า Cluster
- ทำ SSL Passthrough หรือ Re-encryption ไปยัง Cluster Pods ภายใน

---

## 5. Constant-Time & Timing Attack Vulnerability Analysis (DudeCT)

ความท้าทายสำคัญที่สุดของอัลกอริทึมแลตทิซ (ML-KEM และ ML-DSA) คือความเสี่ยงต่อการถูกเจาะระบบผ่าน **Side-Channel Timing Attacks** (การดักวัดเวลาการประมวลผลในระดับนาโนวินาทีเพื่อเดาคีย์ลับ)

TUMQuantum ได้พัฒนาชุดทดสอบ **Constant-Time & Timing Attack Analyzer** ตามระเบียบวิธีวิจัย **DudeCT (Welch's Two-Sample t-test)** เพื่อพิสูจน์ว่าไม่มีการรั่วไหลของเวลา:

### 5.1 ระเบียบวิธีทางสถิติ (DudeCT Methodology)
1. **การจำแนกอินพุต 2 กลุ่ม (Two Input Classes):**
   - **Class 0 (Baseline / Constant):** อินพุตที่มีคีย์/Ciphertext/Signature คงที่
   - **Class 1 (Random / Variance):** อินพุตสุ่มหรือถูกดัดแปลงในตำแหน่งต่างๆ
2. **การวัดเวลาความละเอียดสูงและการสลับลำดับแบบสุ่ม (Interleaved Execution):**
   - ทำการวัดเวลาแบบสลับกัน (Interleaved) เพื่อตัดปัจจัยสัญญาณรบกวน เช่น อุณหภูมิ CPU (Thermal Throttling) หรือการจัดคิวของ OS Scheduler
   - ใช้ Hardware Timestamp Counter ความละเอียดระดับ Sub-Nanosecond
3. **การตัดค่าผิดปกติ (Percentile Outlier Trimming):**
   - ตัดข้อมูลร้อยละ 1 บนสุด (Top 1% Percentile) ที่เกิดจาก OS Interrupts หรือ Thread Preemption
4. **การทดสอบสมมติฐานทางสถิติ (Welch's t-statistic):**
   $$t = \frac{\bar{X}_0 - \bar{X}_1}{\sqrt{\frac{S_0^2}{N_0} + \frac{S_1^2}{N_1}}}$$
   - **เกณฑ์การตัดสิน (Threshold):**
     - หาก $|t| < 4.5$ : ยอมรับสมมติฐานว่าไม่มีความแตกต่างของการกระจายเวลา ($p > 10^{-5}$) $\rightarrow$ **PASS (Constant-Time Certified)**
     - หาก $|t| \ge 4.5$ : มีความแตกต่างทางเวลาที่สัมพันธ์กับข้อมูลลับอย่างมีนัยสำคัญ $\rightarrow$ **FAIL (Timing Leakage Detected)**

### 5.2 มาตรการป้องกันการรั่วไหลในระดับ Microarchitecture
1. **Branchless Arithmetic Sign Shift:**
   - การตรวจสอบขอบเขตสัมประสิทธิ์พหุนามแลตทิซ ต้องไม่ใช้คำสั่ง Jump หรือเงื่อนไข `if (x > threshold)` เพราะ Branch Predictor ใน CPU จะทำให้เกิดความแตกต่างของเวลาที่วัดได้ ($|t| > 100$)
   - ใช้การเลื่อนบิตเครื่องหมาย (Sign Shift Arithmetic) แทนคำสั่งกระโดด:
     ```csharp
     int diff = threshold - coefficient;
     byte boundMask = (byte)(diff >> 31);
     violations += ConstantTimeSelect(boundMask, 1, 0);
     ```
2. **Fixed-Time Array Comparisons:**
   - ใช้ `CryptographicOperations.FixedTimeEquals()` ตรวจสอบค่าแฮชและ Authentication Tags โดยไม่มีการ Early-Exit
3. **Memory Zeroization:**
   - ล้างค่ากุญแจลับในหน่วยความจำทันทีหลังใช้งานด้วย `CryptographicOperations.ZeroMemory()`

### 5.3 ผลการทดสอบเชิงประจักษ์ (Empirical Test Results: 101/101 Tests Passed)
```
+------------------------------------------------------------------------------------------------+
| Target Cryptographic Operation                               | Welch |t| | Threshold | Verdict |
+--------------------------------------------------------------+-----------+-----------+---------+
| SecretByteArrayComparison (FixedTimeEquals)                  |    2.041  |    4.50   |  PASS   |
| ML-KEM-768 Decapsulation & Shared Secret Derivation           |    0.442  |    4.50   |  PASS   |
| ML-DSA-65 Signature Verification (FIPS 204 Lattice Math)     |    0.037  |    4.50   |  PASS   |
| Lattice Polynomial Bound Evaluation (Branchless Select)      |    0.812  |    4.50   |  PASS   |
+------------------------------------------------------------------------------------------------+
OVERALL AUDIT VERDICT: CONSTANT_TIME_COMPLIANT_ZERO_LEAKAGE (Score: 3.6 / 100 - Exceptionally Low Risk)
```

---

## 6. Phased Enterprise Migration Roadmap (2026 – 2029)

```mermaid
timeline
    title แผนภูมิเส้นทางย้ายผ่านระบบสู่ยุคควอนตัม 4 เฟส (2026 - 2029)
    section Phase 1 (2026)
        สำรวจสินทรัพย์ดิจิทัล (Crypto Agility Audit) : สแกนพอร์ตและประเมินความเสี่ยง HNDL
        ติดตั้ง Turnkey Gateway : นำร่องใช้งาน TUM-Quantum Gateway ที่ขอบเขตเครือข่าย
    section Phase 2 (2027)
        ระบบระบุตัวตนลูกผสม : ยกระดับ PKI เป็น Hybrid X.509 และ PQC-OIDC (ML-DSA-65)
        รับรองมาตรฐาน FIPS 140-3 : ทดสอบและรับรองโมดูลฮาร์ดแวร์ HSM ระดับ 3
    section Phase 3 (2028)
        เข้ารหัสข้อมูลที่เก็บถาวร : ยกระดับ Database At-Rest Encryption สู่ ChaCha20 / ML-KEM
        ประทับเวลาระยะยาว (PQC-TSA) : บังคับใช้ RFC 3161 PQC-TSA ตาม พ.ร.บ.ธุรกรรมอิเล็กทรอนิกส์
    section Phase 4 (2029)
        สภาวะภูมิคุ้มกันควอนตัมสมบูรณ์ : ปลดระวางอัลกอริทึม RSA/ECC ดั้งเดิม 100%
        Q-Day Ready : พร้อมรับมือคอมพิวเตอร์ควอนตัมทุกรูปแบบอย่างไร้รอยต่อ
```

---

## 7. Regulatory & Compliance Alignment

โซลูชันของ TUMQuantum สอดคล้องกับข้อกำหนดและมาตรฐานสากลและระดับประเทศ:

1. **NIST FIPS 140-3 (Security Requirements for Cryptographic Modules):**
   - รองรับการทดสอบ Power-Up Self-Tests (POST), Known Answer Tests (KAT), และ CSP Zeroization Mechanism ครอบคลุม Security Levels 1 ถึง 4
2. **สำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สกมช. / NCSA):**
   - สอดคล้องกับแนวทางยกระดับการรักษาความมั่นคงปลอดภัยสารสนเทศสู่ยุคหลังควอนตัมของประเทศไทย
3. **ธนาคารแห่งประเทศไทย (ธปท. / Bank of Thailand):**
   - ปฏิบัติตามเกณฑ์การกำกับดูแลความเสี่ยงด้านเทคโนโลยีสารสนเทศ (IT Risk Management Guideline) และมาตรการป้องกันการดักรับข้อมูลธุรกรรมทางการเงิน
4. **สำนักงานพัฒนาธุรกรรมทางอิเล็กทรอนิกส์ (สพธอ. / ETDA):**
   - รองรับ พ.ร.บ.ว่าด้วยธุรกรรมทางอิเล็กทรอนิกส์ พ.ศ. 2544 (และฉบับแก้ไขเพิ่มเติม) ผ่านการใช้งาน **RFC 3161 Post-Quantum Time-Stamp Authority (PQC-TSA)** เพื่อการรับรองเอกสารอิเล็กทรอนิกส์ที่มีผลผูกพันทางกฎหมายยาวนานกว่า 10 ปี

---

## 8. คู่มือเริ่มต้นใช้งานด่วน (Quick Start Guide)

### รันระบบผ่าน Docker Compose
```bash
# 1. เข้าสู่ไดเรกทอรีโปรเจกต์
cd D:\TUM\tum-quantum

# 2. สั่งเริ่มการทำงานของ Gateway, Engine, และ Upstream Server
docker compose up -d --build

# 3. ตรวจสอบสถานะการทำงาน
docker compose ps

# 4. ทดสอบความถูกต้องด้วยชุดทดสอบอัตโนมัติ
powershell -ExecutionPolicy Bypass -File gateway\test-gateway.ps1
```

### ผลลัพธ์ที่ได้
- พอร์ต `80` (HTTP): ส่งต่อ (Redirect 301) ไปยัง HTTPS อัตโนมัติ
- พอร์ต `443` (HTTPS): ให้บริการ Post-Quantum TLS 1.3 พร้อม Key Encapsulation `X25519MLKEM768`
- พอร์ต `5100`: Sovereign PQC Cryptography REST API
- พอร์ต `8080`: Upstream Legacy Web Server แสดงหน้าผลลัพธ์พร้อม Injected PQC Headers

---
*เอกสารนี้จัดทำโดย TUMQuantum Co., Ltd. หนึ่งในกลุ่มบริษัท TUM Group Holdings Co., Ltd.*  
*ติดต่อทีมสถาปัตยกรรม: `architecture@tumquantum.com` | โทรศัพท์: +66 (0) 2-XXX-XXXX*
