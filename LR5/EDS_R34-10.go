package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// Кривая y^2 = x^3 + a*x + b (mod p) в проективных якобиевых координатах:
// (X, Y, Z) соответствует аффинной точке (X/Z^2, Y/Z^3), так что при
// сложении не нужна дорогая операция обращения по модулю.
type Curve struct {
	P, A, B *big.Int
	Q       *big.Int // порядок подгруппы, порождённой G
	Gx, Gy  *big.Int
}

type jPoint struct {
	X, Y, Z *big.Int // Z = 0 — бесконечно удалённая точка
}

type Affine struct {
	X, Y *big.Int
}

func hex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("плохое hex-число: " + s)
	}
	return v
}

// Тестовые параметры из приложения к ГОСТ Р 34.10-2012 (256 бит).
func gostTestCurve() *Curve {
	return &Curve{
		P:  hex("8000000000000000000000000000000000000000000000000000000000000431"),
		A:  big.NewInt(7),
		B:  hex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
		Q:  hex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
		Gx: big.NewInt(2),
		Gy: hex("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
	}
}

func (c *Curve) mod(x *big.Int) *big.Int { return x.Mod(x, c.P) }

func (c *Curve) infinity() jPoint {
	return jPoint{big.NewInt(1), big.NewInt(1), big.NewInt(0)}
}

func (c *Curve) toJacobian(a Affine) jPoint {
	return jPoint{new(big.Int).Set(a.X), new(big.Int).Set(a.Y), big.NewInt(1)}
}

// возвращает ok=false для бесконечно удалённой точки
func (c *Curve) toAffine(p jPoint) (Affine, bool) {
	if p.Z.Sign() == 0 {
		return Affine{}, false
	}
	zi := new(big.Int).ModInverse(p.Z, c.P)
	zi2 := c.mod(new(big.Int).Mul(zi, zi))
	zi3 := c.mod(new(big.Int).Mul(zi2, zi))
	return Affine{
		X: c.mod(new(big.Int).Mul(p.X, zi2)),
		Y: c.mod(new(big.Int).Mul(p.Y, zi3)),
	}, true
}

func (c *Curve) OnCurve(a Affine) bool {
	left := c.mod(new(big.Int).Mul(a.Y, a.Y))
	right := new(big.Int).Mul(a.X, a.X)
	right.Mul(right, a.X)
	right.Add(right, new(big.Int).Mul(c.A, a.X))
	right.Add(right, c.B)
	c.mod(right)
	return left.Cmp(right) == 0
}

func (c *Curve) double(p jPoint) jPoint {
	if p.Z.Sign() == 0 || p.Y.Sign() == 0 {
		return c.infinity()
	}
	y2 := c.mod(new(big.Int).Mul(p.Y, p.Y))
	// S = 4*X*Y^2
	s := c.mod(new(big.Int).Mul(p.X, y2))
	s.Lsh(s, 2)
	c.mod(s)
	// M = 3*X^2 + a*Z^4
	z2 := c.mod(new(big.Int).Mul(p.Z, p.Z))
	m := new(big.Int).Mul(p.X, p.X)
	m.Mul(m, big.NewInt(3))
	z4 := new(big.Int).Mul(z2, z2)
	m.Add(m, z4.Mul(z4, c.A))
	c.mod(m)

	// X' = M^2 - 2S
	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, new(big.Int).Lsh(s, 1))
	c.mod(x3)
	// Y' = M*(S - X') - 8*Y^4
	y4 := c.mod(new(big.Int).Mul(y2, y2))
	y3 := new(big.Int).Sub(s, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, y4.Lsh(y4, 3))
	c.mod(y3)
	// Z' = 2*Y*Z
	z3 := new(big.Int).Mul(p.Y, p.Z)
	z3.Lsh(z3, 1)
	c.mod(z3)

	return jPoint{x3, y3, z3}
}

func (c *Curve) add(p, q jPoint) jPoint {
	if p.Z.Sign() == 0 {
		return q
	}
	if q.Z.Sign() == 0 {
		return p
	}
	z1sq := c.mod(new(big.Int).Mul(p.Z, p.Z))
	z2sq := c.mod(new(big.Int).Mul(q.Z, q.Z))
	u1 := c.mod(new(big.Int).Mul(p.X, z2sq))
	u2 := c.mod(new(big.Int).Mul(q.X, z1sq))
	s1 := c.mod(new(big.Int).Mul(p.Y, new(big.Int).Mul(z2sq, q.Z)))
	s2 := c.mod(new(big.Int).Mul(q.Y, new(big.Int).Mul(z1sq, p.Z)))

	if u1.Cmp(u2) == 0 {
		if s1.Cmp(s2) != 0 {
			return c.infinity() // q = -p
		}
		return c.double(p)
	}

	h := c.mod(new(big.Int).Sub(u2, u1))
	r := c.mod(new(big.Int).Sub(s2, s1))
	h2 := c.mod(new(big.Int).Mul(h, h))
	h3 := c.mod(new(big.Int).Mul(h2, h))
	u1h2 := c.mod(new(big.Int).Mul(u1, h2))

	// X3 = R^2 - H^3 - 2*U1*H^2
	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, h3)
	x3.Sub(x3, new(big.Int).Lsh(u1h2, 1))
	c.mod(x3)
	// Y3 = R*(U1*H^2 - X3) - S1*H^3
	y3 := new(big.Int).Sub(u1h2, x3)
	y3.Mul(y3, r)
	y3.Sub(y3, new(big.Int).Mul(s1, h3))
	c.mod(y3)
	// Z3 = H*Z1*Z2
	z3 := new(big.Int).Mul(p.Z, q.Z)
	z3.Mul(z3, h)
	c.mod(z3)

	return jPoint{x3, y3, z3}
}

// k*P методом двоичного разложения, от старшего бита к младшему
func (c *Curve) ScalarMult(pt Affine, k *big.Int) (Affine, bool) {
	base := c.toJacobian(pt)
	acc := c.infinity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = c.double(acc)
		if k.Bit(i) == 1 {
			acc = c.add(acc, base)
		}
	}
	return c.toAffine(acc)
}

// u*P + v*R
func (c *Curve) combine(u *big.Int, p Affine, v *big.Int, r Affine) (Affine, bool) {
	a := c.toJacobian(p)
	b := c.toJacobian(r)
	acc := c.infinity()
	for i := max(u.BitLen(), v.BitLen()) - 1; i >= 0; i-- {
		acc = c.double(acc)
		if u.Bit(i) == 1 {
			acc = c.add(acc, a)
		}
		if v.Bit(i) == 1 {
			acc = c.add(acc, b)
		}
	}
	return c.toAffine(acc)
}

// ---------- ключи ----------

type PrivateKey struct {
	D *big.Int
}

type PublicKey struct {
	Pt Affine // Q = d*P
}

// случайное число из диапазона [1, q-1]
func (c *Curve) randScalar() *big.Int {
	v, err := rand.Int(rand.Reader, new(big.Int).Sub(c.Q, big.NewInt(1)))
	if err != nil {
		panic(err)
	}
	return v.Add(v, big.NewInt(1))
}

func (c *Curve) GenerateKeys() (*PrivateKey, *PublicKey) {
	d := c.randScalar()
	q, _ := c.ScalarMult(Affine{c.Gx, c.Gy}, d)
	return &PrivateKey{d}, &PublicKey{q}
}

// ---------- хэш и подпись ----------

// e = H(m) mod q, при e = 0 берётся 1 (так требует стандарт).
func (c *Curve) hashToScalar(msg []byte) *big.Int {
	h := sha256.Sum256(msg)
	e := new(big.Int).SetBytes(h[:])
	e.Mod(e, c.Q)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

type Signature struct {
	R, S *big.Int
}

func (c *Curve) Sign(priv *PrivateKey, msg []byte) Signature {
	e := c.hashToScalar(msg)
	g := Affine{c.Gx, c.Gy}

	for {
		k := c.randScalar()
		pt, ok := c.ScalarMult(g, k)
		if !ok {
			continue
		}
		r := new(big.Int).Mod(pt.X, c.Q)
		if r.Sign() == 0 {
			continue
		}
		// s = (r*d + k*e) mod q
		s := new(big.Int).Mul(r, priv.D)
		s.Add(s, new(big.Int).Mul(k, e))
		s.Mod(s, c.Q)
		if s.Sign() == 0 {
			continue
		}
		return Signature{r, s}
	}
}

func (c *Curve) inRange(x *big.Int) bool {
	return x.Sign() > 0 && x.Cmp(c.Q) < 0
}

func (c *Curve) Verify(pub *PublicKey, msg []byte, sig Signature) bool {
	if !c.inRange(sig.R) || !c.inRange(sig.S) {
		return false
	}
	e := c.hashToScalar(msg)
	v := new(big.Int).ModInverse(e, c.Q)

	// z1 = s*v, z2 = -r*v (mod q);  C = z1*P + z2*Q
	z1 := new(big.Int).Mul(sig.S, v)
	z1.Mod(z1, c.Q)
	z2 := new(big.Int).Mul(sig.R, v)
	z2.Neg(z2).Mod(z2, c.Q)

	pt, ok := c.combine(z1, Affine{c.Gx, c.Gy}, z2, pub.Pt)
	if !ok {
		return false
	}
	return new(big.Int).Mod(pt.X, c.Q).Cmp(sig.R) == 0
}

// ---------- проверки и демонстрация ----------

func (c *Curve) selfCheck() {
	g := Affine{c.Gx, c.Gy}
	fmt.Println("G лежит на кривой:", c.OnCurve(g))
	_, notInf := c.ScalarMult(g, c.Q)
	fmt.Println("q*G = O (порядок точки верный):", !notInf)
	fmt.Println()
}

func demo(c *Curve, msg string, priv *PrivateKey, pub *PublicKey) {
	fmt.Println("=== ЭЦП по ГОСТ Р 34.10 ===")
	fmt.Println("Сообщение:", msg)

	sig := c.Sign(priv, []byte(msg))
	fmt.Printf("r = %x\ns = %x\n", sig.R, sig.S)

	// подпись одного и того же сообщения каждый раз разная из-за k
	sig2 := c.Sign(priv, []byte(msg))
	fmt.Println("Вторая подпись отличается от первой:", sig.R.Cmp(sig2.R) != 0)

	ok := c.Verify(pub, []byte(msg), sig)
	fmt.Println("Подлинная подпись:", ok)

	bad := c.Verify(pub, []byte(msg), Signature{sig.R, new(big.Int).Add(sig.S, big.NewInt(1))})
	fmt.Println("Подделанная подпись:", bad)

	changed := c.Verify(pub, []byte(msg+"!"), sig)
	fmt.Println("Подпись под изменённым текстом:", changed)

	_, otherPub := c.GenerateKeys()
	wrongKey := c.Verify(otherPub, []byte(msg), sig)
	fmt.Println("Проверка чужим открытым ключом:", wrongKey)

	if ok && !bad && !changed && !wrongKey {
		fmt.Println("УСПЕХ")
	} else {
		fmt.Println("ОШИБКА")
	}
	fmt.Println()
}

func main() {
	c := gostTestCurve()
	c.selfCheck()

	priv, pub := c.GenerateKeys()
	fmt.Printf("Закрытый ключ d: %x\n", priv.D)
	fmt.Printf("Открытый ключ Q: x=%x\n                 y=%x\n\n", pub.Pt.X, pub.Pt.Y)

	// TODO: подставить ФИО друга
	demo(c, "Нижегородский государственный технический университет", priv, pub)
	demo(c, "Иванов Иван Иванович", priv, pub)
}
