# คู่มือใช้ secure-project-baseline

## ใช้ทำอะไร

เป็น Skill ส่วนตัวให้ AI เริ่มงานแบบ security-by-design ตั้งแต่ก่อนออกแบบ/เขียนโปรเจกต์ ไม่ใช่ค่อยสแกนท้ายงาน ครอบคลุมเว็บ, API, PWA, mobile/desktop และบริการเบื้องหลัง โดยเลือกข้อกำหนดตามความเสี่ยงจริง ไม่บังคับใส่ระบบล็อกอินให้เว็บสาธารณะที่ไม่จำเป็น

## เริ่มใช้ใน Hermes

โหลดด้วย `/skill secure-project-baseline` แล้วสั่งงานตามปกติ เช่น:

> สร้าง Web app สำหรับ ... ใช้ secure-project-baseline ก่อนออกแบบและเขียนโค้ด เลือกข้อกำหนดให้เหมาะกับข้อมูล/สิทธิ์ของโปรเจกต์ เก็บหลักฐานผลทดสอบจริง และห้ามเรียก production-ready ถ้ายังมีข้อที่ตรวจไม่ครบ

Skill นี้เพิ่มในคลังโปรไฟล์ default แล้ว แต่ไม่ได้ติดตั้ง hook ที่รับประกันว่าโหลดทุกครั้ง สำหรับการส่งงานให้ AI ตัวอื่น ให้ส่งทั้งโฟลเดอร์และผสาน templates/AGENTS.security.md เข้ากับคำสั่งของโปรเจกต์ โดยไม่ทับกฎเดิม

## ด่านการทำงาน

1. ก่อนโค้ด: สำรวจทุกผู้ให้บริการที่โปรเจกต์ใช้งานจริง ไม่ใช่แค่ Firebase เช่น Hosting/VPS, Auth, DB, Storage, CDN/WAF, CI/CD, AI/API, Payment, Email/SMS, Monitoring และ Backup แต่ละรายต้องมี target/environment เจ้าของระบบ controls และหลักฐานแยกกัน ระบุข้อมูล, ผู้ใช้/สิทธิ์, tenant, จุดเชื่อมต่อ, threat model และมาตรฐานเป้าหมาย
2. ระหว่างโค้ด: ใช้การป้องกันที่ trusted server/rules จริง มี negative tests ไม่ใช่แค่ซ่อนปุ่ม
3. ก่อนปล่อย: ตรวจหลักฐานที่ตรงรุ่นโค้ด ผล build/test/scan และข้อเท็จจริงที่ hosting/IdP จริง สิ่งที่ยังตรวจไม่ได้ต้องแจ้งตรง ๆ
4. สรุปใน RELEASE.md ว่าตรวจอะไร ผ่านอะไร และเหลืออะไร ไม่อ้าง OWASP/กฎหมาย compliant แบบเหมารวม

## สิ่งที่ได้ในโปรเจกต์เมื่อรัน init

- docs/security/PROFILE.md
- docs/security/THREAT-MODEL.md
- docs/security/security-controls.json

เริ่มต้นทุก control เป็น pending โดยตั้งใจ AI ต้องทำงานและเก็บหลักฐานก่อนเปลี่ยนสถานะ สคริปต์ไม่แก้ app, ไม่ deploy, ไม่เรียก AI/API เสียเงิน และไม่สแกน production

## สถานะ

- pass: มีหลักฐานการตรวจจริงที่ตรง source/build ref
- fail/pending: ยังไม่พร้อมปล่อย production
- na: ไม่เกี่ยวกับโปรเจกต์พร้อมเหตุผลเฉพาะ ไม่ใช่ข้ออ้างว่ายังไม่ทำ
- accepted-risk: เฉพาะข้อที่อนุญาต ต้องมีผู้อนุมัติ หลักฐาน issue และวันหมดอายุ; high/critical และขอบเขตสำคัญที่กำหนดยกเว้นไม่ได้

ตัวตรวจเอกสารเช็กความครบ รูปแบบ อายุ hash และ source ref เท่านั้น ไม่สามารถพิสูจน์ว่าหลักฐานเขียนจริงหรือแอปปลอดภัย ต้องใช้ร่วมกับผลทดสอบจริงและการรีวิว หากต้องการบังคับจริง ให้ทำ CI required checks + branch/deployment protection ซึ่งต้องติดตั้งและตรวจแยกในแต่ละโปรเจกต์

## แหล่งอ้างอิง

ดู references/sources.md: ASVS 5.0.0 เป็นฐานการตรวจ, OWASP Top 10:2025 เป็นรายการความเสี่ยง, API Security Top 10:2023, MASVS/MASTG สำหรับ mobile และ NIST SP 800-63B-4 สำหรับ authentication ไม่ใช่ใบรับรอง และไม่ใช่คำปรึกษากฎหมาย

ข้อปรับจากเช็กลิสต์เดิม: password-only ขั้นต่ำตาม NIST ปัจจุบันคือ 15 ตัว; MFA/password policy ขึ้นกับสถาปัตยกรรม; TOTP ไม่ phishing-resistant เท่า passkeys; ไม่เปลี่ยนรหัสผู้ใช้ทั้งหมดตามเวลาโดยไม่มีเหตุ; consent ไม่ใช่ฐานกฎหมายเดียว; CSRF/OIDC/BaaS rules/AI tools เป็นขอบเขตที่ต้องประเมินเพิ่ม
