// Перемикання алгоритмів
document.getElementById("algorithm").addEventListener("change", () => {
    const alg = document.getElementById("algorithm").value;

    document.getElementById("dsa_params").classList.toggle("hidden", alg !== "dsa");
    document.getElementById("ecdsa_params").classList.toggle("hidden", alg !== "ecdsa");

    document.getElementById("dsa_verify").classList.toggle("hidden", alg !== "dsa");
    document.getElementById("ecdsa_verify").classList.toggle("hidden", alg !== "ecdsa");
});


// ----------------------
// DSA Математика
// ----------------------
function modInv(a, m) {
    // обернене по модулю (розширений алгоритм Євкліда)
    a = BigInt(a);
    m = BigInt(m);
    let m0 = m, x0 = 0n, x1 = 1n;

    while (a > 1n) {
        let q = a / m;
        [a, m] = [m, a % m];
        [x0, x1] = [x1 - q * x0, x0];
    }
    return (x1 + m0) % m0;
}

function dsaSign(msg, p, q, g, x, k) {
    msg = BigInt("0x" + sha1(msg));
    p = BigInt(p); q = BigInt(q);
    g = BigInt(g); x = BigInt(x); k = BigInt(k);

    const r = (g ** k % p) % q;
    const s = (modInv(k, q) * (msg + x * r)) % q;

    return { r, s };
}

function dsaVerify(msg, r, s, p, q, g, y) {
    msg = BigInt("0x" + sha1(msg));
    p = BigInt(p); q = BigInt(q); g = BigInt(g);
    r = BigInt(r); s = BigInt(s); y = BigInt(y);

    const w = modInv(s, q);
    const u1 = (msg * w) % q;
    const u2 = (r * w) % q;

    const v = ((g ** u1 * y ** u2) % p) % q;

    return v === r;
}


// ----------------------
// ECDSA (дуже спрощена модель)
// ----------------------
// Ми не реалізуємо реальну еліптичну криву! 
// Тільки навчальну модель з додаванням точок мод n.

function ecdsaSign(msg, n, d, k, Px) {
    msg = BigInt("0x" + sha1(msg));
    n = BigInt(n); d = BigInt(d);
    k = BigInt(k); Px = BigInt(Px);

    const r = Px * k % n;
    const s = (modInv(k, n) * (msg + d * r)) % n;

    return { r, s };
}

function ecdsaVerify(msg, r, s, n, Qx, Px) {
    msg = BigInt("0x" + sha1(msg));
    n = BigInt(n); r = BigInt(r); s = BigInt(s);
    Qx = BigInt(Qx); Px = BigInt(Px);

    const w = modInv(s, n);
    const u1 = msg * w % n;
    const u2 = r * w % n;

    const X = (u1 * Px + u2 * Qx) % n;

    return X === r;
}


// SHA-1 (спрощена JS-версія)
function sha1(msg) {
    return CryptoJS.SHA1(msg).toString();
}


// ----------------------
// Обробники кнопок
// ----------------------
function signMessage() {
    const alg = document.getElementById("algorithm").value;
    const msg = document.getElementById("sign_message").value;

    let r, s;

    if (alg === "dsa") {
        let p = dsa_p.value, q = dsa_q.value, g = dsa_g.value;
        let x = dsa_x.value, k = dsa_k.value;

        const sig = dsaSign(msg, p, q, g, x, k);
        r = sig.r; s = sig.s;
    } else {
        let n = ecdsa_n.value, d = ecdsa_d.value, k = ecdsa_k.value;
        let Px = ecdsa_x1.value;

        const sig = ecdsaSign(msg, n, d, k, Px);
        r = sig.r; s = sig.s;
    }

    signature.value = r + "\n" + s;
}

function verifySignature() {
    const alg = document.getElementById("algorithm").value;
    const msg = document.getElementById("verify_message").value;
    const r = verify_r.value;
    const s = verify_s.value;

    let ok = false;

    if (alg === "dsa") {
        ok = dsaVerify(
            msg, r, s,
            dsa_p2.value,
            dsa_q2.value,
            dsa_g2.value,
            dsa_y2.value
        );
    } else {
        ok = ecdsaVerify(
            msg, r, s,
            ecdsa_n2.value,
            ecdsa_Qx2.value,
            ecdsa_Px2.value
        );
    }

    verify_result.value = ok ? "Підпис ВІРНИЙ" : "Підпис НЕВІРНИЙ";
}
