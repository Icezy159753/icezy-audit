# เริ่มโปรเจกต์ด้วยกติกาความปลอดภัยสำหรับหลาย AI

## โปรเจกต์ใหม่

ติดตั้ง baseline ครั้งเดียวต่อเครื่องด้วย `icezy-audit install --apply` (ดู README ของ repo) แล้วสั่ง `/icezy start` (Codex ใช้ `$icezy start`) ให้ AI ผสานไฟล์ AGENTS.md, CLAUDE.md, GEMINI.md, .github และ .cursor ไว้ที่รากโปรเจกต์ ไฟล์เหล่านี้ชี้ไปที่ skill `icezy` ที่ติดตั้งไว้ในเครื่อง ไม่ต้องคัดลอก baseline ลงโปรเจกต์ ผู้ร่วมงานทุกคนต้องติดตั้ง icezy-audit บนเครื่องตัวเองด้วย

เปิด/เริ่มเซสชันใหม่ของ coding agent จากรากโปรเจกต์ ยอมรับ workspace trust เฉพาะโปรเจกต์ที่เชื่อถือได้ แล้วบอกงานที่ต้องการ ไม่จำเป็นต้องพิมพ์ย้ำกติกาทั้งหมดทุกครั้ง

## โปรเจกต์เดิม

อย่าแตกไฟล์ทับ AGENTS.md/CLAUDE.md/GEMINI.md หรือ .github/.cursor ที่มีอยู่ ให้ผสานเฉพาะกติกานี้เข้ากับไฟล์เดิม โดยเก็บคำสั่งเดิมครบ หากมี AGENTS.override.md หรือกฎย่อยที่มีลำดับสูงกว่า ต้องตรวจความขัดแย้งก่อน อย่าแก้ config ผู้ใช้ทั้งเครื่องหรือกฎองค์กรเงียบ ๆ

## ไฟล์ไหนใช้กับอะไร

- Codex: AGENTS.md เป็นคำสั่งระดับโปรเจกต์
- Claude Code: CLAUDE.md import AGENTS.md
- Gemini CLI: GEMINI.md import AGENTS.md
- GitHub Copilot: .github/copilot-instructions.md; ความรองรับแตกต่างตาม client/surface
- Cursor: .cursor/rules/security-baseline.mdc ตั้ง alwaysApply=true และมี AGENTS.md เป็นกติกากลาง
- เครื่องมืออื่นที่อ่าน AGENTS.md: ใช้กติกากลางได้เมื่อเวอร์ชัน/การตั้งค่ารองรับ ต้องเช็กเอกสารจริง

ตัวโมเดล GPT/Claude/Gemini ไม่ใช่ตัวเลือกว่าจะอ่านไฟล์อะไร ตัว coding client เป็นผู้โหลด context ตัวอย่างเช่นใช้ GPT ใน Cursor ก็จะใช้กฎของ Cursor

## ตรวจว่าอ่านจริง

AI ถูกขอให้แจ้งสั้น ๆ ในสถานะเริ่มงานว่าอ่าน baseline อะไรและขาดสิทธิ์ตรงไหน แต่คำพูดนี้ไม่ใช่หลักฐานรับประกัน ตรวจหน้าจอ/context ของเครื่องมือด้วย: Codex ใช้การตรวจคำสั่งที่โหลดตามเวอร์ชัน, Claude Code ดู project memory/context และ Gemini CLI ใช้ /memory show (หลังเพิ่มไฟล์อาจต้องเริ่มใหม่หรือ reload ตาม client) หากไม่ได้อ่าน ให้สั่ง `/icezy start` (Codex ใช้ `$icezy start`) ก่อนเริ่มงาน

## ข้อจำกัดที่ต้องรู้

- ไม่ใช่โปรแกรมเฝ้าทุกโมเดลหรือรับประกัน 100% ว่าจะทำตาม
- ChatGPT/Claude/Gemini แบบเว็บแชตทั่วไปไม่ได้อ่าน local folder นี้เอง ต้องอัปโหลดไฟล์/เพิ่ม Project instructions หรือใช้เครื่องมือที่เข้าถึง workspace
- ไฟล์ถูกปิด/ignore/truncate หรือมีกฎ override อาจทำให้ context ไม่ครบ ตรวจใน client จริงก่อนเชื่อ
- ไม่ใช่ระบบสแกนทุกบริการอัตโนมัติ ตัว Skill สั่งให้ AI สำรวจ/ทดสอบตาม scope และสิทธิ์จริง
- หากต้องการบล็อกการปล่อยงานจริง ต้องผูกผลทดสอบกับ protected CI และสิทธิ์ Deploy แยก
- อย่าใส่ชุดนี้ใน public/ หรือเผยแพร่ docs/security ที่มีข้อมูลระบบส่วนตัวขึ้นเว็บสาธารณะ

อ่านคู่มือไทยเพิ่มเติมที่ references/README-th.md ในโฟลเดอร์ baseline ที่ติดตั้งไว้ (`~/.icezy-audit/releases/<sha>/baseline/`)
