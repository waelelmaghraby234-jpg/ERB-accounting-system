# Holding ERP Cloud Starter

هذه **نواة تشغيلية** وليست ERP نهائياً. تحتوي على:

- PostgreSQL schema للمجموعة والشركات والحسابات والقيود.
- API مبني بـ FastAPI.
- تسجيل دخول JWT وحساب مدير مجموعة أولي.
- إنشاء وعرض الشركات ودليل حسابات المجموعة والحسابات المحلية.
- إنشاء قيد متوازن داخل Transaction واحدة.
- ميزان مراجعة لكل شركة وميزان مراجعة مجمع.
- Dockerfile وملف Render Blueprint.

## المعمارية

- قاعدة البيانات: Supabase PostgreSQL.
- البرنامج/API: Render Docker Web Service.
- الكود: GitHub private repository.
- الاستخدام: رابط HTTPS صادر من Render، ثم دومين مخصص لاحقاً.

## 1. تشغيل محلي

ثبت Docker Desktop، ثم أنشئ ملف `.env` من `.env.example` وعدّل القيم.

```bash
docker build -t holding-erp .
docker run --rm -p 8000:8000 --env-file .env holding-erp
```

افتح:

- `http://localhost:8000`
- `http://localhost:8000/docs`

## 2. إعداد Supabase

1. أنشئ مشروعاً جديداً.
2. من زر **Connect** انسخ Session Pooler أو رابط الاتصال المناسب للسيرفر طويل التشغيل.
3. ضع الرابط في متغير `DATABASE_URL` مع `sslmode=require`.
4. التطبيق ينفذ `database/001_schema.sql` تلقائياً عندما تكون `AUTO_MIGRATE=true`.
5. بعد أول تشغيل ناجح، يفضّل جعل `AUTO_MIGRATE=false` وإدارة التعديلات بمigrations مرقمة.

## 3. رفع الكود إلى GitHub

```bash
git init
git add .
git commit -m "Initial Holding ERP starter"
git branch -M main
git remote add origin YOUR_PRIVATE_GITHUB_REPOSITORY_URL
git push -u origin main
```

لا ترفع ملف `.env` ولا كلمة مرور قاعدة البيانات إلى GitHub.

## 4. النشر على Render

1. اختر **New > Blueprint** أو **New > Web Service**.
2. اربط المستودع الخاص على GitHub.
3. Render سيقرأ `render.yaml` و`Dockerfile`.
4. أدخل الأسرار:
   - `DATABASE_URL`
   - `ADMIN_EMAIL`
   - `ADMIN_PASSWORD`
5. اجعل `JWT_SECRET` قيمة عشوائية طويلة؛ يمكن لـ Render توليدها من `render.yaml`.
6. بعد النشر افتح رابط Render ثم `/docs` لاختبار الـ API.

## 5. أول إعداد داخل البرنامج

1. ادخل بحساب `ADMIN_EMAIL` و`ADMIN_PASSWORD`.
2. أنشئ الشركة القابضة من `/api/companies`.
3. أنشئ الشركات التابعة وحدد `parent_company_id` للشركة القابضة.
4. أنشئ دليل حسابات المجموعة `/api/group-accounts`.
5. اربط الحسابات المحلية لكل شركة بالدليل الموحد `/api/accounts`.
6. أدخل القيود `/api/vouchers`.
7. استخرج الميزان من `/api/trial-balance` أو `/api/consolidated-trial-balance`.

## تنبيهات قبل الإنتاج

- الواجهة الحالية واجهة اختبار وليست شاشة محاسب نهائية.
- أضف صلاحيات تفصيلية Roles/Permissions واعتماد القيود وفترات مالية وإغلاق شهري.
- أنشئ DB role محدوداً للتطبيق بدلاً من استخدام حساب مالك قاعدة البيانات.
- فعّل نسخاً احتياطية مدفوعة، مراقبة، سجل تدقيق Audit Log، وMFA.
- لا تضع `DATABASE_URL` أو `JWT_SECRET` في المتصفح أو داخل JavaScript العام.
- اختبر الاسترجاع من النسخ الاحتياطية، وليس مجرد وجود النسخة.
