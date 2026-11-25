// Accounts & password security (frontend prototype).
//
// Passwords are hashed with PBKDF2-SHA256 (Web Crypto) using a random 16-byte salt per user;
// only the salt + hash are kept. NOTE: everything still lives in this browser's localStorage,
// so this protects the password itself, not the data. Real protection needs a backend that
// stores the hashes and enforces login limits on the server.
import { generateUserId, isValidUzPhone, session, users, type PwRecord, type User } from "./mardikor";

export const PBKDF2_ITER = 600_000; // OWASP's recommended minimum for PBKDF2-HMAC-SHA256
export const MIN_PW = 8;
export const MAX_PW = 128;
export const MAX_FAILED = 5;
export const LOCK_MINUTES = 15;

/** Demo admin accounts seeded on first launch. They must change the password on first login. */
export const DEMO_ADMIN_PASSWORD = "Admin2026!";
export const SEED_ADMINS = [
  { id: "MK000001", phone: "+998990000001", name: "Bosh administrator", adminTitle: "Bosh administrator" },
  { id: "MK000002", phone: "+998990000002", name: "Moderator", adminTitle: "Moderator" },
];

const enc = new TextEncoder();
const toB64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function derive(password: string, salt: string, iter: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64(salt), iterations: iter }, key, 256);
  return toB64(bits);
}

/** Length-independent comparison so the check does not stop at the first different character. */
function safeEqual(a: string, b: string) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

export async function hashPassword(password: string): Promise<PwRecord> {
  const salt = toB64(crypto.getRandomValues(new Uint8Array(16)));
  return { alg: "PBKDF2-SHA256", iter: PBKDF2_ITER, salt, hash: await derive(password, salt, PBKDF2_ITER) };
}

export async function verifyPassword(password: string, rec: PwRecord) {
  return safeEqual(await derive(password, rec.salt, rec.iter), rec.hash);
}

const COMMON = ["12345678", "123456789", "1234567890", "password", "parol123", "qwerty123", "11111111", "00000000", "admin123", "daywork1"];

/** Returns the list of rule violations (empty = password is acceptable). */
export function passwordIssues(pw: string, phone?: string): string[] {
  const out: string[] = [];
  if (pw.length < MIN_PW) out.push(`Kamida ${MIN_PW} ta belgi`);
  if (pw.length > MAX_PW) out.push(`Ko‘pi bilan ${MAX_PW} ta belgi`);
  if (!/[A-Za-z]/.test(pw)) out.push("Kamida bitta harf");
  if (!/\d/.test(pw)) out.push("Kamida bitta raqam");
  if (COMMON.includes(pw.toLowerCase())) out.push("Juda oddiy parol");
  const digits = phone?.replace(/\D/g, "").slice(-9);
  if (digits && pw.replace(/\D/g, "").includes(digits)) out.push("Telefon raqamingizni parol qilmang");
  return out;
}

/** 0 (very weak) … 4 (strong) — for the strength meter only. */
export function passwordStrength(pw: string): number {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= MIN_PW) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s++;
  return passwordIssues(pw).length ? Math.min(s, 1) : Math.max(s, 2);
}

type Result<T = User> = { ok: true; user: T } | { ok: false; error: string };
const fullPhone = (digits: string) => "+998" + digits;

/** Creates the demo admin accounts once (if no admin exists yet). */
export async function ensureSeedAdmins() {
  if (users.all().some((u) => u.role === "admin")) return;
  const list = users.all();
  for (const a of SEED_ADMINS) {
    if (list.some((u) => u.id === a.id || u.phone === a.phone)) continue;
    list.push({
      ...a, region: "Toshkent shahri", district: "Mirobod", balance: 0, completed: 0, role: "admin",
      pw: await hashPassword(DEMO_ADMIN_PASSWORD), mustChangePw: true, failed: 0, lockUntil: 0, createdAt: Date.now(),
    });
  }
  users.save(list);
}

export const phoneTaken = (digits: string) => !!users.byPhone(fullPhone(digits));

export async function login(digits: string, password: string): Promise<Result> {
  const generic = "Telefon raqam yoki parol noto‘g‘ri.";
  if (!isValidUzPhone(digits) || !password) return { ok: false, error: generic };
  const u = users.byPhone(fullPhone(digits));
  if (!u) { await derive(password, toB64(new Uint8Array(16)), PBKDF2_ITER); return { ok: false, error: generic }; } // same timing as a real check
  const now = Date.now();
  if (u.lockUntil > now) return { ok: false, error: `Ko‘p marta xato kiritildi. ${Math.ceil((u.lockUntil - now) / 60000)} daqiqadan keyin urinib ko‘ring.` };
  if (u.blocked) return { ok: false, error: "Hisobingiz administrator tomonidan bloklangan." };
  if (!(await verifyPassword(password, u.pw))) {
    const failed = u.failed + 1;
    if (failed >= MAX_FAILED) {
      users.update(u.id, { failed: 0, lockUntil: now + LOCK_MINUTES * 60000 });
      return { ok: false, error: `${MAX_FAILED} marta xato. Hisob ${LOCK_MINUTES} daqiqaga bloklandi.` };
    }
    users.update(u.id, { failed });
    return { ok: false, error: `${generic} Qolgan urinish: ${MAX_FAILED - failed}` };
  }
  users.update(u.id, { failed: 0, lockUntil: 0 });
  session.set(u.id);
  return { ok: true, user: users.byId(u.id)! };
}

export async function register(d: { digits: string; name: string; region: string; district: string; password: string }): Promise<Result> {
  if (!isValidUzPhone(d.digits)) return { ok: false, error: "Telefon raqam noto‘g‘ri." };
  if (phoneTaken(d.digits)) return { ok: false, error: "Bu raqam allaqachon ro‘yxatdan o‘tgan. Kirish bo‘limidan foydalaning." };
  const issues = passwordIssues(d.password, d.digits);
  if (issues.length) return { ok: false, error: "Parol talablarga javob bermaydi: " + issues.join(", ") };
  let id = generateUserId();
  while (users.byId(id)) id = generateUserId();
  const user: User = {
    id, phone: fullPhone(d.digits), name: d.name.trim(), region: d.region, district: d.district, balance: 0, completed: 0,
    role: "user", pw: await hashPassword(d.password), failed: 0, lockUntil: 0, createdAt: Date.now(),
  };
  users.save([...users.all(), user]);
  session.set(id);
  return { ok: true, user };
}

/** The user changes their own password; the current password is required. */
export async function changePassword(userId: string, current: string, next: string): Promise<Result> {
  const u = users.byId(userId);
  if (!u) return { ok: false, error: "Foydalanuvchi topilmadi." };
  if (!(await verifyPassword(current, u.pw))) return { ok: false, error: "Joriy parol noto‘g‘ri." };
  if (current === next) return { ok: false, error: "Yangi parol eskisidan farq qilishi kerak." };
  const issues = passwordIssues(next, u.phone);
  if (issues.length) return { ok: false, error: "Parol talablarga javob bermaydi: " + issues.join(", ") };
  users.update(u.id, { pw: await hashPassword(next), mustChangePw: false, failed: 0, lockUntil: 0 });
  return { ok: true, user: users.byId(u.id)! };
}

/** "Forgot password": called only after the SMS code for this phone was confirmed. */
export async function resetPassword(digits: string, next: string): Promise<Result> {
  const u = users.byPhone(fullPhone(digits));
  if (!u) return { ok: false, error: "Bu raqam ro‘yxatdan o‘tmagan." };
  const issues = passwordIssues(next, u.phone);
  if (issues.length) return { ok: false, error: "Parol talablarga javob bermaydi: " + issues.join(", ") };
  users.update(u.id, { pw: await hashPassword(next), mustChangePw: false, failed: 0, lockUntil: 0 });
  return { ok: true, user: users.byId(u.id)! };
}

/** Admin: sets a random temporary password that the user must change at next login. */
export async function adminResetPassword(userId: string): Promise<string> {
  const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
  const rnd = crypto.getRandomValues(new Uint32Array(10));
  const temp = Array.from(rnd.slice(0, 6), (n) => abc[n % abc.length]).join("") + Array.from(rnd.slice(6), (n) => n % 10).join("");
  users.update(userId, { pw: await hashPassword(temp), mustChangePw: true, failed: 0, lockUntil: 0 });
  return temp;
}
// ---- Email OTP (qo'shimcha usul, telefon/Telegram tizimiga tegmaydi) ----
const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_STORE_KEY = "mk_email_otps";

type PendingOtp = { code: string; expiresAt: number; tries: number };

function readOtps(): Record<string, PendingOtp> {
  if (typeof window === "undefined") return {};
  try {
    return JSON.parse(localStorage.getItem(OTP_STORE_KEY) || "{}");
  } catch {
    return {};
  }
}

function writeOtps(map: Record<string, PendingOtp>) {
  localStorage.setItem(OTP_STORE_KEY, JSON.stringify(map));
}

export const isValidEmail = (email: string) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
export const emailTaken = (email: string) => !!users.byEmail(email);

export async function sendEmailOtp(email: string): Promise<{ ok: boolean; error?: string; demoCode?: string }> {
  const clean = email.trim().toLowerCase();
  if (!isValidEmail(clean)) return { ok: false, error: "Email manzil noto‘g‘ri." };

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const map = readOtps();
  map[clean] = { code, expiresAt: Date.now() + OTP_TTL_MS, tries: 0 };
  writeOtps(map);

  const SERVICE_ID = "";
  const TEMPLATE_ID = "";
  const PUBLIC_KEY = "";

  if (SERVICE_ID && TEMPLATE_ID && PUBLIC_KEY) {
    try {
      const res = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service_id: SERVICE_ID,
          template_id: TEMPLATE_ID,
          user_id: PUBLIC_KEY,
          template_params: {
            to_email: clean,
            otp_code: code,
            message: `Sizning Daywork.uz tasdiqlash kodingiz: ${code}`,
          },
        }),
      });
      if (!res.ok) return { ok: false, error: "Email yuborishda xatolik yuz berdi." };
      return { ok: true };
    } catch {
      return { ok: false, error: "Internet ulanishida xatolik." };
    }
  }

  return { ok: true, demoCode: code };
}

export function verifyEmailOtp(email: string, code: string): { ok: boolean; error?: string } {
  const clean = email.trim().toLowerCase();
  const map = readOtps();
  const rec = map[clean];
  if (!rec) return { ok: false, error: "Avval kod yuboring." };
  if (Date.now() > rec.expiresAt) return { ok: false, error: "Kod muddati tugagan. Qayta yuboring." };
  if (rec.tries >= 3) return { ok: false, error: "3 marta xato kiritildi. Yangi kod oling." };

  if (rec.code !== code.trim()) {
    rec.tries += 1;
    writeOtps(map);
    return { ok: false, error: `Kod noto‘g‘ri. Qolgan urinish: ${3 - rec.tries}` };
  }

  delete map[clean];
  writeOtps(map);
  return { ok: true };
}

export async function loginByEmailOtp(email: string, code: string): Promise<Result> {
  const clean = email.trim().toLowerCase();
  const chk = verifyEmailOtp(clean, code);
  if (!chk.ok) return { ok: false, error: chk.error! };

  const u = users.byEmail(clean);
  if (!u) return { ok: false, error: "Bu email ro‘yxatdan o‘tmagan. Ro‘yxatdan o‘tish bo‘limiga o‘ting." };
  if (u.blocked) return { ok: false, error: "Hisobingiz administrator tomonidan bloklangan." };

  users.update(u.id, { failed: 0, lockUntil: 0 });
  session.set(u.id);
  return { ok: true, user: users.byId(u.id)! };
}

export async function registerByEmailOtp(d: {
  email: string;
  code: string;
  name: string;
  region: string;
  district: string;
}): Promise<Result> {
  const clean = d.email.trim().toLowerCase();
  if (!isValidEmail(clean)) return { ok: false, error: "Email manzil noto‘g‘ri." };
  if (emailTaken(clean)) return { ok: false, error: "Bu email allaqachon ro‘yxatdan o‘tgan." };

  const chk = verifyEmailOtp(clean, d.code);
  if (!chk.ok) return { ok: false, error: chk.error! };

  const randPw = crypto.randomUUID() + "Aa1!";
  let id = generateUserId();
  while (users.byId(id)) id = generateUserId();

  const user: User = {
    id,
    phone: "",
    email: clean,
    name: d.name.trim(),
    region: d.region,
    district: d.district,
    balance: 0,
    completed: 0,
    role: "user",
    pw: await hashPassword(randPw),
    failed: 0,
    lockUntil: 0,
    createdAt: Date.now(),
  };

  users.save([...users.all(), user]);
  session.set(id);
  return { ok: true, user };
}
