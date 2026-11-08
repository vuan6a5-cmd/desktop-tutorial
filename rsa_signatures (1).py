# -*- coding: utf-8 -*-
"""
Chủ đề 8: Chương trình phần mềm thực hiện hệ chữ ký điện tử RSA
Yêu cầu:
 a) Nhập các tham số đầu vào của hệ chữ ký trên màn hình giao diện
 b) Tính toán và hiển thị các tham số khoá công khai, khóa bí mật
 c) Tính toán và hiển thị chữ ký lên văn bản M
 d) Kiểm tra xác thực chữ ký đã ký lên văn bản M
 * Hiển thị kết quả các bước quá trình tính toán và kết quả cuối cùng trên giao diện

Chạy: python rsa_signature.py   (Python 3.8+, chỉ dùng thư viện chuẩn)
"""
import hashlib
import math
import random
import tkinter as tk
from tkinter import ttk, messagebox


# ======================= PHẦN TOÁN HỌC =======================
def is_prime(n, rounds=40):
    """Kiểm tra số nguyên tố bằng Miller-Rabin."""
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small:
        if n == sp:
            return True
        if n % sp == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    """Sinh số nguyên tố ngẫu nhiên có đúng `bits` bit."""
    while True:
        if bits < 3:
            bits = 3
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(c):
            return c


def ext_gcd_steps(a, b):
    """Euclid mở rộng, trả về (gcd, x, y, các dòng log). a*x + b*y = gcd."""
    rows = []
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        rows.append((q, old_r, r, old_s, old_t))
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t, rows


def hash_message(msg: str) -> int:
    return int(hashlib.sha256(msg.encode("utf-8")).hexdigest(), 16)


# ======================= GIAO DIỆN =======================
class RSASignatureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Chữ ký điện tử RSA - Nhóm 8")
        self.geometry("1280x780")
        self.minsize(1100, 700)

        self.n = self.phi = self.e = self.d = None
        self.p = self.q = None

        self._build_ui()

    # ---------- dựng giao diện ----------
    def _build_ui(self):
        root = ttk.Frame(self, padding=8)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=0)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        left = ttk.Frame(root)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 8))
        right = ttk.LabelFrame(root, text=" Các bước tính toán chi tiết ", padding=6)
        right.grid(row=0, column=1, sticky="nsew")

        # --- a) Tham số đầu vào ---
        fa = ttk.LabelFrame(left, text=" a) Nhập tham số đầu vào ", padding=8)
        fa.pack(fill="x")
        self.var_p = tk.StringVar()
        self.var_q = tk.StringVar()
        self.var_e = tk.StringVar(value="65537")
        self.var_bits = tk.StringVar(value="16")

        ttk.Label(fa, text="Số nguyên tố p:").grid(row=0, column=0, sticky="w")
        ttk.Entry(fa, textvariable=self.var_p, width=52).grid(row=0, column=1, pady=2)
        ttk.Label(fa, text="Số nguyên tố q:").grid(row=1, column=0, sticky="w")
        ttk.Entry(fa, textvariable=self.var_q, width=52).grid(row=1, column=1, pady=2)
        ttk.Label(fa, text="Số mũ công khai e:").grid(row=2, column=0, sticky="w")
        ttk.Entry(fa, textvariable=self.var_e, width=52).grid(row=2, column=1, pady=2)

        fb = ttk.Frame(fa)
        fb.grid(row=3, column=0, columnspan=2, sticky="we", pady=(6, 0))
        ttk.Label(fb, text="Độ dài mỗi số nguyên tố (bit):").pack(side="left")
        ttk.Combobox(fb, textvariable=self.var_bits, width=6, state="readonly",
                     values=["6", "8", "10", "12", "16", "20", "24", "32", "64", "128", "256", "512", "1024"]).pack(side="left", padx=4)
        ttk.Button(fb, text="Sinh p, q ngẫu nhiên", command=self.on_generate).pack(side="left", padx=4)
        ttk.Button(fb, text="Tính khóa", command=self.on_keygen).pack(side="left")

        # --- b) Khóa ---
        fk = ttk.LabelFrame(left, text=" b) Khóa công khai / khóa bí mật ", padding=8)
        fk.pack(fill="x", pady=6)
        self.txt_pub = self._labeled_text(fk, "Khóa công khai (n, e):", 2)
        self.txt_prv = self._labeled_text(fk, "Khóa bí mật (n, d) và p, q, φ(n):", 4)

        # --- c) Ký ---
        fs = ttk.LabelFrame(left, text=" c) Tạo chữ ký lên văn bản M ", padding=8)
        fs.pack(fill="x")
        ttk.Label(fs, text="Văn bản M:").pack(anchor="w")
        self.txt_msg = tk.Text(fs, height=2, width=62, wrap="word")
        self.txt_msg.pack(fill="x")
        self.txt_msg.insert("1.0", "Xin chao, day la van ban can ky.")
        ttk.Button(fs, text="Ký văn bản", command=self.on_sign).pack(anchor="w", pady=4)
        ttk.Label(fs, text="Chữ ký S (hệ thập phân):").pack(anchor="w")
        self.txt_sig = tk.Text(fs, height=2, width=62, wrap="char")
        self.txt_sig.pack(fill="x")

        # --- d) Kiểm tra ---
        fv = ttk.LabelFrame(left, text=" d) Kiểm tra xác thực chữ ký ", padding=8)
        fv.pack(fill="x", pady=6)
        ttk.Label(fv, text="Văn bản M' cần kiểm tra (có thể sửa để thử giả mạo):").pack(anchor="w")
        self.txt_vmsg = tk.Text(fv, height=2, width=62, wrap="word")
        self.txt_vmsg.pack(fill="x")
        ttk.Label(fv, text="Chữ ký S' cần kiểm tra (thập phân):").pack(anchor="w")
        self.txt_vsig = tk.Text(fv, height=2, width=62, wrap="char")
        self.txt_vsig.pack(fill="x")
        bf = ttk.Frame(fv)
        bf.pack(fill="x", pady=4)
        ttk.Button(bf, text="Lấy M và S từ phần ký", command=self.on_copy).pack(side="left")
        ttk.Button(bf, text="Kiểm tra chữ ký", command=self.on_verify).pack(side="left", padx=6)
        self.lbl_result = tk.Label(fv, text="Kết quả: (chưa kiểm tra)", font=("Arial", 12, "bold"),
                                   anchor="w")
        self.lbl_result.pack(fill="x")

        # --- Nhật ký ---
        self.log = tk.Text(right, wrap="word", font=("Consolas", 10))
        sb = ttk.Scrollbar(right, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log.pack(fill="both", expand=True)
        self.log.tag_configure("h", font=("Consolas", 11, "bold"), foreground="#0b5394")
        self.log.tag_configure("ok", foreground="#0a7d2c", font=("Consolas", 10, "bold"))
        self.log.tag_configure("bad", foreground="#c00000", font=("Consolas", 10, "bold"))
        ttk.Button(right, text="Xóa nhật ký", command=lambda: self.log.delete("1.0", "end")).pack(
            side="bottom", anchor="e", pady=(4, 0))

    def _labeled_text(self, parent, label, h):
        ttk.Label(parent, text=label).pack(anchor="w")
        t = tk.Text(parent, height=h, width=62, wrap="char")
        t.pack(fill="x", pady=(0, 4))
        return t

    # ---------- tiện ích ----------
    def w(self, text="", tag=None):
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")

    @staticmethod
    def set_text(widget, value):
        widget.delete("1.0", "end")
        widget.insert("1.0", value)

    @staticmethod
    def get_int(var, name):
        s = var.get().strip().replace(" ", "")
        try:
            return int(s)
        except ValueError:
            raise ValueError(f"{name} phải là một số nguyên.")

    # ---------- sự kiện ----------
    def on_generate(self):
        bits = int(self.var_bits.get())
        self.w(f"=== Sinh số nguyên tố ngẫu nhiên {bits} bit ===", "h")
        p = gen_prime(bits)
        q = gen_prime(bits)
        while q == p:
            q = gen_prime(bits)
        self.var_p.set(str(p))
        self.var_q.set(str(q))
        self.w(f"p = {p}")
        self.w(f"q = {q}")
        phi = (p - 1) * (q - 1)
        for cand in (65537, 257, 17, 11, 7, 5, 3):
            if cand < phi and math.gcd(cand, phi) == 1:
                self.var_e.set(str(cand))
                self.w(f"Tự chọn e = {cand} (nguyên tố cùng nhau với φ(n) = {phi})\n")
                break
        else:
            self.w("Không tự chọn được e, hãy sinh lại p, q.\n", "bad")

    def on_keygen(self):
        try:
            p = self.get_int(self.var_p, "p")
            q = self.get_int(self.var_q, "q")
            e = self.get_int(self.var_e, "e")
        except ValueError as ex:
            messagebox.showerror("Lỗi nhập liệu", str(ex))
            return

        self.w("=== b) TẠO KHÓA RSA ===", "h")
        # Kiểm tra p, q
        if not is_prime(p):
            messagebox.showerror("Lỗi", "p không phải số nguyên tố.")
            self.w("p KHÔNG phải số nguyên tố.", "bad")
            return
        if not is_prime(q):
            messagebox.showerror("Lỗi", "q không phải số nguyên tố.")
            self.w("q KHÔNG phải số nguyên tố.", "bad")
            return
        if p == q:
            messagebox.showerror("Lỗi", "p và q phải khác nhau.")
            return
        self.w("Bước 1: Kiểm tra p, q là số nguyên tố (Miller-Rabin) -> p, q đều nguyên tố.")

        n = p * q
        phi = (p - 1) * (q - 1)
        self.w(f"Bước 2: n = p * q = {n}")
        self.w(f"Bước 3: φ(n) = (p-1)(q-1) = {phi}")

        if not (1 < e < phi):
            messagebox.showerror("Lỗi", "Cần 1 < e < φ(n).")
            return
        g = math.gcd(e, phi)
        self.w(f"Bước 4: Chọn e = {e}, kiểm tra gcd(e, φ(n)) = {g}")
        if g != 1:
            messagebox.showerror("Lỗi", f"gcd(e, φ(n)) = {g} ≠ 1. Hãy chọn e khác (hoặc p, q khác).")
            self.w("-> e không nguyên tố cùng nhau với φ(n). Chọn lại e.", "bad")
            return

        self.w("Bước 5: Tính d = e^(-1) mod φ(n) bằng thuật toán Euclid mở rộng:")
        gg, x, y, rows = ext_gcd_steps(e, phi)
        shown = rows if len(rows) <= 12 else rows[:6] + [None] + rows[-5:]
        self.w(f"   {'thương q':>14} {'a':>14} {'b':>14}")
        for r in shown:
            if r is None:
                self.w("   ... (rút gọn các bước giữa) ...")
            else:
                qq, a, b, _, _ = r
                a_s = str(a) if len(str(a)) < 14 else str(a)[:10] + ".."
                b_s = str(b) if len(str(b)) < 14 else str(b)[:10] + ".."
                q_s = str(qq) if len(str(qq)) < 14 else str(qq)[:10] + ".."
                self.w(f"   {q_s:>14} {a_s:>14} {b_s:>14}")
        self.w(f"   Số bước Euclid: {len(rows)}; gcd = {gg}")
        d = x % phi
        self.w(f"   => d = {d}")
        ok = (e * d) % phi == 1
        self.w(f"Bước 6: Kiểm tra e*d mod φ(n) = {(e * d) % phi}  ->  {'ĐÚNG' if ok else 'SAI'}",
               "ok" if ok else "bad")

        self.n, self.phi, self.e, self.d, self.p, self.q = n, phi, e, d, p, q
        self.set_text(self.txt_pub, f"n = {n}\ne = {e}")
        self.set_text(self.txt_prv, f"d = {d}\np = {p}\nq = {q}\nφ(n) = {phi}")
        self.w(f"\nKhóa công khai: PU = (e, n) = ({e}, n)")
        self.w("Khóa bí mật   : PR = (d, n)")
        if n.bit_length() < 257:
            self.w("Lưu ý: n < 2^256, giá trị băm SHA-256 sẽ bị rút gọn mod n "
                   "(chỉ phù hợp để minh họa). Dùng p, q ≥ 128 bit để an toàn hơn.", "bad")
        self.w("")

    def on_sign(self):
        if self.n is None:
            messagebox.showwarning("Chưa có khóa", "Hãy bấm 'Tính khóa' trước.")
            return
        msg = self.txt_msg.get("1.0", "end-1c")
        if not msg:
            messagebox.showwarning("Thiếu văn bản", "Hãy nhập văn bản M.")
            return
        self.w("=== c) TẠO CHỮ KÝ ===", "h")
        self.w(f"Văn bản M = {msg!r}")
        h = hash_message(msg)
        self.w(f"Bước 1: H(M) = SHA-256(M) (hex) = {h:064x}")
        self.w(f"        H(M) (thập phân)        = {h}")
        hn = h % self.n
        if h >= self.n:
            self.w(f"Bước 2: H(M) ≥ n nên lấy m = H(M) mod n = {hn}")
        else:
            self.w(f"Bước 2: m = H(M) = {hn}  (m < n)")
        s = pow(hn, self.d, self.n)
        self.w("Bước 3: Chữ ký S = m^d mod n")
        self.w(f"        S = {s}")
        self.w(f"        S (hex) = {s:x}\n", "ok")
        self.set_text(self.txt_sig, str(s))
        self.on_copy()

    def on_copy(self):
        self.set_text(self.txt_vmsg, self.txt_msg.get("1.0", "end-1c"))
        self.set_text(self.txt_vsig, self.txt_sig.get("1.0", "end-1c").strip())

    def on_verify(self):
        if self.n is None:
            messagebox.showwarning("Chưa có khóa", "Hãy bấm 'Tính khóa' trước.")
            return
        msg = self.txt_vmsg.get("1.0", "end-1c")
        sig_s = self.txt_vsig.get("1.0", "end-1c").strip().replace(" ", "")
        try:
            s = int(sig_s)
        except ValueError:
            messagebox.showerror("Lỗi", "Chữ ký S' phải là số nguyên thập phân.")
            return
        self.w("=== d) KIỂM TRA CHỮ KÝ ===", "h")
        self.w(f"Văn bản M' = {msg!r}")
        self.w(f"Chữ ký S'  = {s}")
        h = hash_message(msg)
        hn = h % self.n
        self.w(f"Bước 1: H(M') = SHA-256(M') (hex) = {h:064x}")
        self.w(f"        m' = H(M') mod n = {hn}")
        v = pow(s, self.e, self.n) if 0 <= s < self.n else None
        if v is None:
            self.w("Chữ ký nằm ngoài khoảng [0, n-1] -> KHÔNG HỢP LỆ", "bad")
            self._set_result(False)
            return
        self.w(f"Bước 2: V = S'^e mod n = {v}")
        self.w(f"Bước 3: So sánh V với m':  V == m' ?  {v == hn}")
        okk = (v == hn)
        if okk:
            self.w("=> CHỮ KÝ HỢP LỆ: văn bản toàn vẹn và đúng người ký.\n", "ok")
        else:
            self.w("=> CHỮ KÝ KHÔNG HỢP LỆ: văn bản hoặc chữ ký đã bị thay đổi.\n", "bad")
        self._set_result(okk)

    def _set_result(self, ok):
        if ok:
            self.lbl_result.config(text="Kết quả: CHỮ KÝ HỢP LỆ ✔", fg="#0a7d2c")
        else:
            self.lbl_result.config(text="Kết quả: CHỮ KÝ KHÔNG HỢP LỆ ✘", fg="#c00000")


if __name__ == "__main__":
    RSASignatureApp().mainloop()