package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

const keyBits = 1024

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
	bigTwo  = big.NewInt(2)
)

// ---------- арифметика ----------

// итеративный расширенный алгоритм Евклида: g = a*x + b*y
func egcd(a, b *big.Int) (g, x, y *big.Int) {
	oldR, r := new(big.Int).Set(a), new(big.Int).Set(b)
	oldS, s := big.NewInt(1), big.NewInt(0)
	oldT, t := big.NewInt(0), big.NewInt(1)

	for r.Sign() != 0 {
		q := new(big.Int).Div(oldR, r)
		oldR, r = r, new(big.Int).Sub(oldR, new(big.Int).Mul(q, r))
		oldS, s = s, new(big.Int).Sub(oldS, new(big.Int).Mul(q, s))
		oldT, t = t, new(big.Int).Sub(oldT, new(big.Int).Mul(q, t))
	}
	return oldR, oldS, oldT
}

func invMod(a, m *big.Int) (*big.Int, error) {
	g, x, _ := egcd(new(big.Int).Mod(a, m), m)
	if g.Cmp(bigOne) != 0 {
		return nil, fmt.Errorf("числа %v и %v не взаимно просты", a, m)
	}
	return x.Mod(x, m), nil
}

// быстрое возведение в степень, разбор показателя с младших битов
func powMod(base, exp, mod *big.Int) *big.Int {
	res := big.NewInt(1)
	b := new(big.Int).Mod(base, mod)
	for i := 0; i < exp.BitLen(); i++ {
		if exp.Bit(i) == 1 {
			res.Mul(res, b).Mod(res, mod)
		}
		b.Mul(b, b).Mod(b, mod)
	}
	return res
}

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	r := new(big.Int).Mul(a, b)
	return r.Div(r, g)
}

// ---------- простые числа: тест Миллера-Рабина ----------

func isProbablePrime(n *big.Int, rounds int) bool {
	if n.Cmp(bigTwo) < 0 {
		return false
	}
	for _, sp := range []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29} {
		p := big.NewInt(sp)
		if n.Cmp(p) == 0 {
			return true
		}
		if new(big.Int).Mod(n, p).Sign() == 0 {
			return false
		}
	}

	// n-1 = 2^s * d, d нечётное
	nm1 := new(big.Int).Sub(n, bigOne)
	d := new(big.Int).Set(nm1)
	s := 0
	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}

	for i := 0; i < rounds; i++ {
		// a из [2, n-2]
		a, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(3)))
		if err != nil {
			panic(err)
		}
		a.Add(a, bigTwo)

		x := powMod(a, d, n)
		if x.Cmp(bigOne) == 0 || x.Cmp(nm1) == 0 {
			continue
		}
		composite := true
		for r := 1; r < s; r++ {
			x.Mul(x, x).Mod(x, n)
			if x.Cmp(nm1) == 0 {
				composite = false
				break
			}
		}
		if composite {
			return false
		}
	}
	return true
}

func randomPrime(bits int) *big.Int {
	for {
		buf := make([]byte, (bits+7)/8)
		if _, err := rand.Read(buf); err != nil {
			panic(err)
		}
		c := new(big.Int).SetBytes(buf)
		c.SetBit(c, bits-1, 1) // ровно bits бит
		c.SetBit(c, bits-2, 1) // чтобы p*q точно имело 2*bits бит
		c.SetBit(c, 0, 1)      // нечётное
		if c.BitLen() == bits && isProbablePrime(c, 32) {
			return c
		}
	}
}

// ---------- ключи ----------

type PublicKey struct {
	N, E *big.Int
}

// храним p, q и CRT-параметры, чтобы расшифровывать быстрее
type PrivateKey struct {
	N, D   *big.Int
	P, Q   *big.Int
	Dp, Dq *big.Int
	QInv   *big.Int
}

func GenerateKeys(bits int) (*PublicKey, *PrivateKey) {
	e := big.NewInt(65537)
	for {
		p := randomPrime(bits / 2)
		q := randomPrime(bits / 2)
		if p.Cmp(q) == 0 {
			continue
		}
		pm1 := new(big.Int).Sub(p, bigOne)
		qm1 := new(big.Int).Sub(q, bigOne)

		// функция Кармайкла λ(n) = lcm(p-1, q-1) вместо φ(n)
		lambda := lcm(pm1, qm1)
		d, err := invMod(e, lambda)
		if err != nil {
			continue // e не подошло к этой паре, берём новую
		}

		n := new(big.Int).Mul(p, q)
		qInv, _ := invMod(q, p)
		priv := &PrivateKey{
			N: n, D: d, P: p, Q: q,
			Dp:   new(big.Int).Mod(d, pm1),
			Dq:   new(big.Int).Mod(d, qm1),
			QInv: qInv,
		}
		return &PublicKey{N: n, E: e}, priv
	}
}

// m = c^d mod n через китайскую теорему об остатках
func (k *PrivateKey) apply(c *big.Int) *big.Int {
	m1 := powMod(c, k.Dp, k.P)
	m2 := powMod(c, k.Dq, k.Q)
	h := new(big.Int).Sub(m1, m2)
	h.Mul(h, k.QInv).Mod(h, k.P)
	return h.Mul(h, k.Q).Add(h, m2)
}

// ---------- шифрование ----------

func (pub *PublicKey) blockLen() int  { return (pub.N.BitLen() - 1) / 8 }
func (pub *PublicKey) cipherLen() int { return (pub.N.BitLen() + 7) / 8 }

// Каждый блок открытого текста предваряется байтом 0x01, чтобы ведущие нули
// не терялись при переводе в число и обратно.
func Encrypt(data []byte, pub *PublicKey) []byte {
	chunk := pub.blockLen() - 1
	cl := pub.cipherLen()

	var out []byte
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		block := append([]byte{0x01}, data[off:end]...)

		m := new(big.Int).SetBytes(block)
		c := powMod(m, pub.E, pub.N)
		out = append(out, c.FillBytes(make([]byte, cl))...)
	}
	return out
}

func Decrypt(data []byte, priv *PrivateKey) []byte {
	cl := (priv.N.BitLen() + 7) / 8

	var out []byte
	for off := 0; off+cl <= len(data); off += cl {
		c := new(big.Int).SetBytes(data[off : off+cl])
		block := priv.apply(c).Bytes()
		out = append(out, block[1:]...) // отбрасываем маркер 0x01
	}
	return out
}

// ---------- подпись ----------

func digest(msg []byte, n *big.Int) *big.Int {
	h := sha256.Sum256(msg)
	return new(big.Int).Mod(new(big.Int).SetBytes(h[:]), n)
}

func Sign(msg []byte, priv *PrivateKey) *big.Int {
	return priv.apply(digest(msg, priv.N))
}

func Verify(msg []byte, sig *big.Int, pub *PublicKey) bool {
	if sig.Sign() <= 0 || sig.Cmp(pub.N) >= 0 {
		return false
	}
	return powMod(sig, pub.E, pub.N).Cmp(digest(msg, pub.N)) == 0
}

// ---------- демонстрации ----------

func short(x *big.Int) string {
	s := x.String()
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}

func demoEncrypt(msg string, pub *PublicKey, priv *PrivateKey) {
	fmt.Println("=== RSA: шифрование ===")
	fmt.Println("Открытый текст:", msg)
	fmt.Printf("Открытый ключ:  n=%s  e=%v\n", short(pub.N), pub.E)

	ct := Encrypt([]byte(msg), pub)
	fmt.Printf("Шифртекст (hex): %x\n", ct)

	pt := string(Decrypt(ct, priv))
	fmt.Println("Расшифровка:", pt)
	report(pt == msg)
}

func demoSign(msg string, pub *PublicKey, priv *PrivateKey) {
	fmt.Println("=== RSA: электронная подпись ===")
	fmt.Println("Сообщение:", msg)

	sig := Sign([]byte(msg), priv)
	fmt.Printf("Подпись (hex): %x\n", sig)

	ok := Verify([]byte(msg), sig, pub)
	fmt.Println("Подлинная подпись:", ok)

	bad := Verify([]byte(msg), new(big.Int).Add(sig, bigOne), pub)
	fmt.Println("Подделанная подпись:", bad)

	changed := Verify([]byte(msg+"!"), sig, pub)
	fmt.Println("Подпись под изменённым текстом:", changed)
	report(ok && !bad && !changed)
}

// модуль 40 бит раскладывается перебором, после чего подпись подделывается
func demoWeakKey() {
	fmt.Println("=== Слабый ключ (40 бит) ===")
	pub, _ := GenerateKeys(40)

	n := pub.N.Uint64()
	var p uint64
	for i := uint64(3); i*i <= n; i += 2 {
		if n%i == 0 {
			p = i
			break
		}
	}
	q := n / p
	fmt.Printf("n = %d = %d * %d\n", n, p, q)

	lambda := lcm(new(big.Int).SetUint64(p-1), new(big.Int).SetUint64(q-1))
	d, _ := invMod(pub.E, lambda)
	stolen := &PrivateKey{
		N: pub.N, D: d,
		P: new(big.Int).SetUint64(p), Q: new(big.Int).SetUint64(q),
	}
	stolen.Dp = new(big.Int).Mod(d, new(big.Int).SetUint64(p-1))
	stolen.Dq = new(big.Int).Mod(d, new(big.Int).SetUint64(q-1))
	stolen.QInv, _ = invMod(stolen.Q, stolen.P)

	msg := []byte("Этого документа я не подписывал")
	fmt.Println("Подделка проходит проверку:", Verify(msg, Sign(msg, stolen), pub))
	fmt.Println()
}

func report(ok bool) {
	if ok {
		fmt.Println("УСПЕХ")
	} else {
		fmt.Println("ОШИБКА")
	}
	fmt.Println()
}

func main() {
	fmt.Printf("Генерация ключей RSA (%d бит)...\n\n", keyBits)
	pub, priv := GenerateKeys(keyBits)

	// TODO: подставить ФИО друга
	msgs := []string{
		"Нижегородский государственный технический университет",
		"Иванов Иван Иванович",
	}
	for _, m := range msgs {
		demoEncrypt(m, pub, priv)
	}
	for _, m := range msgs {
		demoSign(m, pub, priv)
	}
	demoWeakKey()
}
