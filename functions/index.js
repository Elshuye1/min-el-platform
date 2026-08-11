/**
 * Min-el Cloud Functions
 * ======================
 * Fixes the three CRITICAL findings from the audit that cannot be fixed in
 * client-side code alone, because they all require something the browser
 * must never be trusted with:
 *   1. verifyReportsPin      — the PIN itself, and the decision to unlock it
 *   2. startTrial             — the rule "12 days, no payment" (business logic)
 *   3. initializeChapaPayment
 *      + chapaWebhook         — the payment secret key, and the decision to
 *                                mark a subscription "paid"
 *
 * Deploy with:
 *   cd functions && npm install
 *   firebase functions:secrets:set CHAPA_SECRET_KEY   (paste CHASECK_TEST-... when prompted)
 *   firebase deploy --only functions
 */

const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

const CHAPA_SECRET_KEY = defineSecret("CHASECK_TEST-sqVRKIzaPX5Jyb33IFayh36eqLvZwfdc");
const REGION = "us-central1"; // matches the URL already hardcoded in owner-dashboard.html

// ---------------------------------------------------------------------------
// Shared helper: look up the caller's own user profile. Never trust a
// companyId/role sent from the client — always derive it from the caller's
// verified uid via Firestore, which only the caller's own login could have
// created (users/{uid} is written once at registration).
// ---------------------------------------------------------------------------
async function getCallerProfile(request) {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "You must be logged in.");
  }
  const snap = await db.collection("users").doc(request.auth.uid).get();
  if (!snap.exists) {
    throw new HttpsError("failed-precondition", "No profile found for this account.");
  }
  return { uid: request.auth.uid, ...snap.data() };
}

// ===========================================================================
// 1. REPORTS PIN — server-side check, never trust the client's comparison
// ===========================================================================
// Fixes: "Client-Side PIN Gate Security Flaw" (seller-dashboard.html).
// The PIN itself now never leaves the server, and the "unlocked" decision is
// made here, not in a JS variable the console can flip. On success we set a
// short-lived custom claim; the client must call getIdTokenResult(true) to
// pick it up, and your Firestore rules for sales/wastage/debts should check
// request.auth.token.reportsUnlockedUntil > request.time (see README section
// "Firestore rules you still need to add" below) — otherwise the report DATA
// itself still loads unconditionally regardless of this claim.
exports.verifyReportsPin = onCall(async (request) => {
  const { pin } = request.data || {};
  if (!pin || typeof pin !== "string") {
    throw new HttpsError("invalid-argument", "PIN is required.");
  }

  const profile = await getCallerProfile(request);
  if (!profile.companyId) {
    throw new HttpsError("failed-precondition", "No company associated with this account.");
  }

  const companySnap = await db.collection("companies").doc(profile.companyId).get();
  const realPin = companySnap.exists ? companySnap.data().reportsPin : null;

  // No PIN set by the Owner at all → nothing to unlock, matches the
  // existing "safe default: never silently blocks a seller" behavior.
  if (!realPin) {
    return { success: true, gated: false };
  }

  if (pin !== realPin) {
    // Deliberately vague — never confirm/deny partial matches or leak
    // anything that narrows down the real PIN.
    return { success: false };
  }

  // Grant a claim valid for 30 minutes. The client must refresh its ID
  // token (getIdTokenResult(true)) after this call for the claim to apply.
  const expiresAt = Date.now() + 30 * 60 * 1000;
  const user = await admin.auth().getUser(request.auth.uid);
  await admin.auth().setCustomUserClaims(request.auth.uid, {
    ...(user.customClaims || {}),
    reportsUnlockedUntil: expiresAt,
    reportsUnlockedCompany: profile.companyId,
  });

  return { success: true, gated: true, expiresAt };
});

// ===========================================================================
// 2. START TRIAL — server decides the plan, price, and dates, never the client
// ===========================================================================
// Fixes: "Client-Driven Subscription Logic" (index.html). Previously the
// browser wrote its own `plan`, `priceEtb`, and `trialEndsAt` straight to
// Firestore — anyone could open the console and grant themselves a paid
// plan for free with no expiry. Now the plan/price whitelist and the trial
// length live only here, and each company can only ever use one free trial.
const PLAN_CATALOG = {
  pro: { priceEtb: 499, label: "Pro" },
  business: { priceEtb: 1499, label: "Business" },
};
const TRIAL_DAYS = 12;

exports.startTrial = onCall(async (request) => {
  const { planId } = request.data || {};
  const plan = PLAN_CATALOG[planId];
  if (!plan) {
    throw new HttpsError("invalid-argument", "Unknown plan.");
  }

  const profile = await getCallerProfile(request);
  if (profile.role !== "owner") {
    throw new HttpsError("permission-denied", "Only the business Owner can change the plan.");
  }
  if (!profile.companyId) {
    throw new HttpsError("failed-precondition", "No company associated with this account.");
  }

  const subRef = db.collection("subscriptions").doc(profile.companyId);
  const companyRef = db.collection("companies").doc(profile.companyId);

  const result = await db.runTransaction(async (tx) => {
    const subSnap = await tx.get(subRef);
    const sub = subSnap.exists ? subSnap.data() : null;

    if (sub && sub.trialUsed) {
      throw new HttpsError("failed-precondition", "This business has already used its free trial.");
    }

    const trialEndsAt = admin.firestore.Timestamp.fromMillis(Date.now() + TRIAL_DAYS * 24 * 60 * 60 * 1000);

    tx.set(subRef, {
      companyId: profile.companyId,
      plan: planId,
      priceEtb: plan.priceEtb,
      status: "trialing",
      trialEndsAt,
      trialUsed: true,
      startedAt: admin.firestore.FieldValue.serverTimestamp(),
      startedBy: request.auth.uid,
      paymentProvider: "chapa",
      paymentStatus: "trial_no_payment",
    }, { merge: true });

    tx.set(companyRef, {
      plan: planId,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    return { trialEndsAt: trialEndsAt.toMillis() };
  });

  return { success: true, plan: planId, label: plan.label, ...result };
});

// ===========================================================================
// 3a. INITIALIZE CHAPA PAYMENT — secret key never touches the browser
// ===========================================================================
// Fixes: "Unauthenticated Payment Endpoint" (owner-dashboard.html). Price
// comes from PLAN_CATALOG above, never from the client. Caller identity is
// verified automatically by onCall (Firebase handles the ID token check —
// no manual Authorization header parsing needed on this side).
exports.initializeChapaPayment = onCall({ secrets: [CHAPA_SECRET_KEY] }, async (request) => {
  const { planId } = request.data || {};
  const plan = PLAN_CATALOG[planId];
  if (!plan) {
    throw new HttpsError("invalid-argument", "Unknown plan.");
  }

  const profile = await getCallerProfile(request);
  if (profile.role !== "owner") {
    throw new HttpsError("permission-denied", "Only the business Owner can pay for a plan.");
  }
  if (!profile.companyId) {
    throw new HttpsError("failed-precondition", "No company associated with this account.");
  }

  const txRef = `minel-${profile.companyId}-${Date.now()}`;

  const chapaRes = await fetch("https://api.chapa.co/v1/transaction/initialize", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${CHAPA_SECRET_KEY.value()}`,
    },
    body: JSON.stringify({
      amount: String(plan.priceEtb),
      currency: "ETB",
      email: request.auth.token.email || "no-reply@min-el.com",
      tx_ref: txRef,
      callback_url: `https://us-central1-min-eli.cloudfunctions.net/chapaWebhook`,
      return_url: "https://min-el.com/owner-dashboard.html?payment=pending",
      customization: {
        title: "Min-el Subscription",
        description: `${plan.label} plan`,
      },
    }),
  });

  const data = await chapaRes.json();
  if (!chapaRes.ok || data.status !== "success") {
    throw new HttpsError("internal", data.message || "Chapa could not start this payment.");
  }

  // Record the pending transaction BEFORE redirecting the user, so the
  // webhook has something authoritative to match against (companyId + plan)
  // instead of trusting whatever Chapa's callback claims.
  await db.collection("pendingPayments").doc(txRef).set({
    companyId: profile.companyId,
    planId,
    priceEtb: plan.priceEtb,
    status: "initialized",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    createdBy: request.auth.uid,
  });

  return { checkout_url: data.data.checkout_url, tx_ref: txRef };
});

// ===========================================================================
// 3b. CHAPA WEBHOOK — the only place a subscription is ever marked "active"
// ===========================================================================
// Chapa calls this directly (server-to-server), signing the payload with
// your secret key. We verify that signature before trusting anything in the
// body — this is what actually prevents "client-side manipulation of active
// plans": the browser is never the one deciding a payment succeeded.
// After deploying, set this exact URL as your webhook in the Chapa
// dashboard (Settings → Webhooks):
//   https://us-central1-min-eli.cloudfunctions.net/chapaWebhook
exports.chapaWebhook = onRequest({ secrets: [CHAPA_SECRET_KEY] }, async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).send("Method not allowed");
    return;
  }

  // Chapa signs with HMAC-SHA256 over the JSON body using your secret key,
  // and sends it as either `Chapa-Signature` or `x-chapa-signature`. Per
  // Chapa's own docs, if both are present at least one must be valid.
  const secret = CHAPA_SECRET_KEY.value();
  const expectedHash = crypto.createHmac("sha256", secret).update(JSON.stringify(req.body)).digest("hex");
  const sigA = req.headers["chapa-signature"];
  const sigB = req.headers["x-chapa-signature"];
  const valid = (sigA && sigA === expectedHash) || (sigB && sigB === expectedHash);

  if (!valid) {
    console.warn("Chapa webhook: signature mismatch — discarding request.");
    res.status(401).send("Invalid signature");
    return;
  }

  const { tx_ref, status } = req.body || {};
  if (!tx_ref) {
    res.status(400).send("Missing tx_ref");
    return;
  }

  const pendingRef = db.collection("pendingPayments").doc(tx_ref);
  const pendingSnap = await pendingRef.get();
  if (!pendingSnap.exists) {
    console.warn(`Chapa webhook: unknown tx_ref ${tx_ref}`);
    res.status(404).send("Unknown transaction");
    return;
  }
  const pending = pendingSnap.data();

  // Double-check directly against Chapa's own verify endpoint too — belt
  // and suspenders, since webhook bodies alone are a common spoofing target
  // even with signature checks, if a secret ever leaked.
  const verifyRes = await fetch(`https://api.chapa.co/v1/transaction/verify/${tx_ref}`, {
    headers: { Authorization: `Bearer ${secret}` },
  });
  const verifyData = await verifyRes.json();
  const reallyPaid = verifyRes.ok && verifyData.status === "success" && verifyData.data && verifyData.data.status === "success";

  if (!reallyPaid) {
    await pendingRef.set({ status: "failed", checkedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
    res.status(200).send("Recorded (not paid)");
    return;
  }

  const subRef = db.collection("subscriptions").doc(pending.companyId);
  const companyRef = db.collection("companies").doc(pending.companyId);
  const batch = db.batch();
  batch.set(subRef, {
    companyId: pending.companyId,
    plan: pending.planId,
    priceEtb: pending.priceEtb,
    status: "active",
    paymentProvider: "chapa",
    paymentStatus: "paid",
    paidAt: admin.firestore.FieldValue.serverTimestamp(),
    trialEndsAt: admin.firestore.FieldValue.delete(),
  }, { merge: true });
  batch.set(companyRef, {
    plan: pending.planId,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });
  batch.set(pendingRef, { status: "paid", paidAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
  await batch.commit();

  res.status(200).send("OK");
});
