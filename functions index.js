const {onCall, HttpsError} = require("firebase-functions/v2/https");
const {setGlobalOptions} = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();

setGlobalOptions({
  region: "us-central1",
  maxInstances: 10
});

const MASTER_UID = "LJVhofYtJ0VsaLUgSIen6UZKvu73";
const LOG_COLL = "adminLogs";

function assertMaster(request) {
  if (!request.auth || !request.auth.uid) {
    throw new HttpsError("unauthenticated", "يجب تسجيل الدخول أولًا.");
  }
  if (request.auth.uid !== MASTER_UID) {
    throw new HttpsError("permission-denied", "هذه العملية للماستر فقط.");
  }
}

function assertUid(uid) {
  if (typeof uid !== "string" || !uid.trim() || uid.length > 128) {
    throw new HttpsError("invalid-argument", "معرّف المستخدم غير صالح.");
  }
}

function randomChars(len, chars) {
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[crypto.randomInt(chars.length)];
  }
  return out;
}

function generateTemporaryPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  let pwd = "";
  let attempts = 0;

  do {
    const a = randomChars(4, chars);
    const b = randomChars(4, chars);
    const c = randomChars(4, chars);
    pwd = a + "-" + b + "-" + c;
    attempts++;
  } while (
    attempts < 12 &&
    (!/[A-Z]/.test(pwd) || !/[a-z]/.test(pwd) || !/[0-9]/.test(pwd))
  );

  return pwd;
}

async function writeAdminLog(entry) {
  try {
    await admin.firestore().collection(LOG_COLL).add({
      ...entry,
      createdAt: new Date().toISOString()
    });
  } catch (e) {
    console.warn("admin security log write failed", e);
  }
}

function getRequestMeta(request) {
  const rr = request.rawRequest || {};
  return {
    ip: rr.ip || (rr.headers && rr.headers["x-forwarded-for"]) || null,
    userAgent: rr.headers ? rr.headers["user-agent"] || null : null
  };
}

exports.masterGeneratePasswordResetLink = onCall(async (request) => {
  assertMaster(request);

  const uid = request.data && request.data.uid;
  assertUid(uid);

  if (uid === MASTER_UID) {
    throw new HttpsError("failed-precondition", "لا يمكن توليد رابط استعادة لحساب الماستر من هنا.");
  }

  let user;
  try {
    user = await admin.auth().getUser(uid);
  } catch (e) {
    throw new HttpsError("not-found", "لم يتم العثور على المستخدم.");
  }

  if (user.disabled) {
    throw new HttpsError("failed-precondition", "هذا الحساب محظور حاليًا.");
  }

  if (!user.email) {
    throw new HttpsError("failed-precondition", "هذا الحساب ليس مرتبطًا ببريد إلكتروني. استخدم كلمة السر المؤقتة.");
  }

  let link;
  try {
    link = await admin.auth().generatePasswordResetLink(user.email);
  } catch (e) {
    console.warn("generatePasswordResetLink failed", e);
    throw new HttpsError("internal", "تعذر توليد رابط الاستعادة.");
  }

  const meta = getRequestMeta(request);

  await writeAdminLog({
    ts: Date.now(),
    uid: request.auth.uid,
    by: request.auth.token && request.auth.token.email ? request.auth.token.email : "Master",
    type: "auth",
    module: "security",
    action: "توليد رابط استعادة كلمة سر",
    targetId: uid,
    targetName: user.email || uid,
    details: "تم توليد رابط مؤقت لإعادة تعيين كلمة السر.",
    ip: meta.ip,
    userAgent: meta.userAgent
  });

  return {
    ok: true,
    email: user.email || "",
    link
  };
});

exports.masterSetTemporaryPassword = onCall(async (request) => {
  assertMaster(request);

  const uid = request.data && request.data.uid;
  assertUid(uid);

  if (uid === MASTER_UID) {
    throw new HttpsError("failed-precondition", "لا يمكن تغيير كلمة سر الماستر من هنا. استخدم صفحة تغيير كلمة السر.");
  }

  let user;
  try {
    user = await admin.auth().getUser(uid);
  } catch (e) {
    throw new HttpsError("not-found", "لم يتم العثور على المستخدم.");
  }

  if (user.disabled) {
    throw new HttpsError("failed-precondition", "هذا الحساب محظور حاليًا.");
  }

  const tempPassword = generateTemporaryPassword();

  try {
    await admin.auth().updateUser(uid, {
      password: tempPassword
    });
  } catch (e) {
    console.warn("updateUser password failed", e);
    throw new HttpsError("internal", "فشل تعيين كلمة السر المؤقتة.");
  }

  try {
    await admin.auth().revokeRefreshTokens(uid);
  } catch (e) {
    console.warn("revokeRefreshTokens failed", e);
  }

  try {
    await admin.auth().setCustomUserClaims(uid, {
      mustChangePassword: true,
      passwordResetByAdmin: true,
      passwordResetAt: Date.now()
    });
  } catch (e) {
    console.warn("setCustomUserClaims failed", e);
  }

  const meta = getRequestMeta(request);

  await writeAdminLog({
    ts: Date.now(),
    uid: request.auth.uid,
    by: request.auth.token && request.auth.token.email ? request.auth.token.email : "Master",
    type: "auth",
    module: "security",
    action: "تعيين كلمة سر مؤقتة",
    targetId: uid,
    targetName: user.email || uid,
    details: "تم تعيين كلمة سر مؤقتة، إغلاق الجلسات القديمة، وإجبار العميل على تغييرها.",
    ip: meta.ip,
    userAgent: meta.userAgent
  });

  return {
    ok: true,
    uid,
    email: user.email || "",
    displayName: user.displayName || "",
    tempPassword
  };
});

exports.selfClearMustChangePassword = onCall(async (request) => {
  if (!request.auth || !request.auth.uid) {
    throw new HttpsError("unauthenticated", "يجب تسجيل الدخول أولًا.");
  }

  const uid = request.auth.uid;

  try {
    await admin.auth().setCustomUserClaims(uid, {
      mustChangePassword: null,
      passwordResetByAdmin: null,
      passwordResetAt: null
    });
  } catch (e) {
    console.warn("selfClearMustChangePassword failed", e);
    throw new HttpsError("internal", "تعذر تحديث صلاحيات الحساب.");
  }

  await writeAdminLog({
    ts: Date.now(),
    uid,
    by: request.auth.token && request.auth.token.email ? request.auth.token.email : "User",
    type: "auth",
    module: "security",
    action: "إزالة إجبار تغيير كلمة السر",
    targetId: uid,
    targetName: request.auth.token && request.auth.token.email ? request.auth.token.email : uid,
    details: "المستخدم غيّر كلمة السر بنفسه.",
    selfService: true
  });

  return { ok: true };
});