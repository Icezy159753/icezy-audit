# Icezy Audit

ติดตั้ง **กติกาความปลอดภัยสำหรับ AI coding agents** ครั้งเดียว แล้วเรียกใช้ในโปรเจกต์ได้โดยไม่ต้องคัดลอก ZIP เอง

> ไม่ใช่ vulnerability scanner, ไม่ได้พิสูจน์โมเดลต้นทาง และไม่ใช่ใบรับรองความปลอดภัย/OWASP compliance คำสั่งนี้โหลด workflow ให้ AI ตรวจ/พัฒนาตามหลักฐานจริง ไม่รับประกันว่า AI จะทำตาม 100%

## ติดตั้งจาก GitHub

ต้องมี **Python 3.11+ และ uv/uvx** บนเครื่อง ไม่ใช้ sudo และไม่ต้องให้ API Key กับตัวติดตั้ง หากยังไม่มี uv ให้ติดตั้งจากเอกสารทางการ https://docs.astral.sh/uv/getting-started/installation/ แล้วเปิด Terminal ใหม่

ดูแผนก่อน (ยังไม่เขียนไฟล์):

```sh
uvx --from "git+https://github.com/Icezy159753/icezy-audit.git@v0.1.4" icezy-audit install --agents claude,codex,gemini,cursor,hermes
```

ติดตั้งจริง:

```sh
uvx --from "git+https://github.com/Icezy159753/icezy-audit.git@v0.1.4" icezy-audit install --agents claude,codex,gemini,cursor,hermes --apply
```

เลือกเฉพาะที่ใช้ได้ เช่น `--agents claude,codex` ไม่จำเป็นต้องมีทุกโปรแกรมติดตั้งอยู่แล้ว คำสั่งเตรียมไฟล์ไว้ให้ แต่ไม่ติดตั้ง coding clients ไม่ล็อกอิน และไม่เปลี่ยนโมเดล/ผู้ให้บริการของพี่

คำสั่ง uvx เดียวกันใช้ใน Terminal บน Windows/macOS/Linux เมื่อมี Python/uv พร้อม ใช้บัญชีผู้ใช้ธรรมดา ไม่ใช่ Administrator/root ทดสอบแพลตฟอร์มจริงตามผล CI/เอกสาร release; อย่าอนุมานว่าทดสอบ native ครบจากการรันบน Linux

ถ้าต้องการเก็บ CLI ไว้ใช้บ่อย:

```sh
uv tool install "git+https://github.com/Icezy159753/icezy-audit.git@v0.1.4"
icezy-audit install --agents claude,codex,gemini,cursor,hermes --apply
```

Tag ช่วยระบุรุ่น แต่เจ้าของ repo ยังย้าย tag ได้ งานที่ต้องการ pin แน่นขึ้นให้แทน `v0.1.4` ด้วย full reviewed commit SHA

## เรียกใน AI

หลังติดตั้ง เปิด session ใหม่ของเครื่องมือจากโฟลเดอร์โปรเจกต์:

- **Claude Code:** `/icezy audit`
- **Gemini CLI:** `/icezy audit`
- **Cursor:** `/icezy audit`
- **Hermes:** `/icezy audit` ในไคลเอนต์ที่รองรับ dynamic skill commands; ถ้ายังไม่เห็นให้โหลด skill `icezy` ผ่านรายการ skills หรือเริ่ม session ใหม่
- **Codex:** `$icezy audit` หรือเลือก `icezy` ใน `/skills` — Codex ใช้ skill mention ไม่ใช่ slash command แบบเดียวกับทุกตัว

`/Icezy Audit` เป็นชื่อแนวคิดที่พี่ขอ แต่ชื่อไฟล์/คำสั่งที่ชุดนี้ติดตั้งคือ `icezy` ตัวเล็ก และ `audit` เป็น argument จึงไม่อ้างว่าตัวพิมพ์ใหญ่/ชื่อมีช่องว่างใช้ตรงกันทุก client

### โหมด

**audit** — อ่านและตรวจ scope ที่ขอเป็นหลัก รายงานสิ่งที่มีหลักฐาน สิ่งที่ยังไม่ตรวจ และข้อควรแก้ ไม่แก้โค้ด/ตั้งค่า ไม่ยิง production scan หรือเสีย quota API เงียบ ๆ ถ้าเป็นโปรเจกต์ว่าง ให้ทำ preflight ระบุสิ่งที่ต้องตัดสินใจ ไม่แต่งผลทดสอบ

**start** — ใช้ security baseline ก่อนออกแบบ/เขียน feature ระบุ data/roles/tenants/threat model และทุก provider ที่ใช้จริง แล้วพัฒนา/ทดสอบภายในงานที่ผู้ใช้อนุญาต

ตัวอย่าง:

```text
/icezy start สร้างเว็บจัดการลูกค้า ใช้ Google login และ Supabase
/icezy audit ตรวจสิทธิ์ tenant และ endpoint export ของโปรเจกต์นี้
```

ใน Codex เปลี่ยน prefix เป็น `$icezy` แทน ส่วนฟังก์ชันอื่นนอก scope ต้องขออนุญาต ไม่ใช่แค่เห็นคำว่า audit แล้วเริ่ม penetration test ทั้งระบบ

## สแกนอัตโนมัติ

สแกนโปรเจกต์แบบอ่านอย่างเดียว ไม่แก้ไฟล์โปรเจกต์ และเก็บรายงานไว้นอกโปรเจกต์:

```sh
uvx --from "git+https://github.com/Icezy159753/icezy-audit.git@v0.1.4" icezy-audit scan ./my-project
```

ตัวสแกนตรวจ 2 ชั้น:

- **ตรวจในตัว (ใช้ได้แม้ไม่มีอินเทอร์เน็ต):**
  - secret/API key ที่หลุดในโค้ดหรือ `.env` รวมถึงตัวแปร `VITE_`/`NEXT_PUBLIC_` ที่เป็นความลับ และ JWT ที่เป็น Supabase `service_role`
  - Supabase: ตารางที่ไม่เปิด RLS, policy `USING (true)`, policy ที่ไม่มี `WITH CHECK`, policy ที่เชื่อ `user_metadata`, ฟังก์ชัน `SECURITY DEFINER`, storage bucket และ Edge Function
  - Firebase: Firestore/Storage/Realtime Database rules ที่เปิดกว้างหรือยังเป็น test mode และไฟล์ service account
  - config ของ Next.js/Vite/hosting เช่น source map, `next/image`, CSP
  - Dockerfile และ lockfile
- **เครื่องมือมาตรฐาน (รันเมื่อเครื่องมีเครื่องมือนั้น):** npm audit, pip-audit, semgrep, bandit, gitleaks, trivy, osv-scanner เครื่องมือที่รันไม่ได้จะรายงานเป็น `NOT_RUN` ไม่นับว่าผ่าน

ตัวเลือก:

- `--offline`: ไม่ใช้อินเทอร์เน็ต
- `--builtin-only`: รันเฉพาะการตรวจในตัว
- `--fail-on high`: คืนค่า exit 1 เมื่อพบปัญหาระดับ High ขึ้นไป ใช้กับ CI
- `--out <dir>`: กำหนดที่เก็บ `report.md` และ `report.json`

ผลที่ได้เป็นจุดที่ต้องตรวจต่อ ไม่ใช่คำตัดสิน ให้ `/icezy audit` ยืนยันกับโค้ดจริงอีกครั้ง

ใช้ใน GitHub Actions: คัดลอก `templates/ci/icezy-security-scan.yml` จาก baseline ไปไว้ที่ `.github/workflows/` ของโปรเจกต์ workflow นี้จะสแกนทุก PR และ fail เมื่อพบปัญหาระดับ High

## ตัวติดตั้งทำอะไร

- เก็บ baseline แบบ content-addressed ไว้ใต้ `~/.icezy-audit/`
- ติดตั้ง adapter เฉพาะ client ที่เลือกไปยัง user-level command/skill directory
- ไม่แตะไฟล์โปรเจกต์หรือ global model/security configuration
- ไม่ส่งข้อมูล/telemetry ไม่เรียกโมเดล ไม่อ่านรหัสผ่านหรือคีย์
- ค่าเริ่มต้นเป็น dry run; ต้องมี `--apply` ถึงเขียนไฟล์
- มีอยู่แล้วแต่ไม่ใช่ไฟล์ที่ตัวติดตั้งจัดการ หรือถูกผู้ใช้แก้ภายหลัง: ปฏิเสธการทับ
- ถอนติดตั้งลบเฉพาะ adapter ที่ยังตรง hash เดิม เก็บของที่แก้เองและ baseline ไว้ ไม่ลบโฟลเดอร์ผู้ใช้แบบ recursive

## อัปเดต / ตรวจสถานะ / ถอน

ใช้ `icezy-audit --help` และคำสั่งย่อย `install`, `status`, `uninstall` สำหรับรายการ options รุ่นที่ติดตั้ง การอัปเดตใช้ installer รุ่นใหม่และต้องมี --apply เช่นเดิม ตรวจไฟล์ที่ผู้ใช้แก้ก่อนเสมอ

ถอนด้วย CLI ที่ติดตั้ง หรือใช้ `uvx --from ... icezy-audit uninstall --apply` ตัวติดตั้งไม่ล้างคำสั่งอื่นหรือโฟลเดอร์โปรเจกต์ baseline เก่าที่เก็บไว้ไม่ถูก garbage-collect อัตโนมัติ

## ข้อจำกัด

- ต้องใช้ coding client ที่อ่าน skill/command บนเครื่องได้ ChatGPT/Claude/Gemini เว็บแชตทั่วไปไม่อ่าน home directory นี้เอง
- Model brand ไม่ใช่ตัวกำหนด command loader เช่น GPT ใน Cursor ใช้คำสั่งของ Cursor
- Workspace trust, overrides, client version และตัว model อาจมีผล ต้องตรวจ context จริงของ client
- ชุดนี้ไม่เปิด auto-hook ทุกงาน ไม่บล็อก Deploy ด้วยตัวเอง ต้องผูก real tests + protected CI + สิทธิ์ deploy แยก
- Scope ครอบคลุมทุก provider ของ **โปรเจกต์ที่ได้รับอนุญาต** ไม่ใช่สิทธิ์สแกนบัญชี/ระบบอื่นทั้งหมด
- Local hashes ไม่ป้องกันผู้โจมตีที่มีสิทธิ์บัญชี OS เดียวกัน และไม่พิสูจน์ความจริงของ evidence/model identity

## Development

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python src/icezy_audit/payload/scripts/test_security_gate.py
python src/icezy_audit/payload/scripts/test_entrypoints.py
uv build
```

Baseline อ้างอิง OWASP ASVS 5.0.0, Top 10:2025, API Security Top 10:2023, MASVS/MASTG และ NIST SP 800-63B-4 โดยตรวจแหล่งต้นทางและเลือกตาม scope ไม่ใช่คำอ้างว่าโค้ดได้รับการรับรอง

ดู `docs/CLIENTS.md` สำหรับหลักฐานวิธี discovery, `docs/security/` สำหรับ threat model/ขอบเขตทดสอบ และ `SECURITY.md` สำหรับแจ้งช่องโหว่
