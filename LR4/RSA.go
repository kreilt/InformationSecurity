package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const keyBits = 1024 //рекомендуемая длина модуля n для обычных задач (из лекции)

func main() {
	if !selfTest() { //сверяем механизм с примерами из лекций
		fmt.Fprintln(os.Stderr, "ошибка механизма шифрования")
		os.Exit(1)
	}

	buf := []byte(input())      //читаем инпут
	n, e, d := genKeys(keyBits) //генерируем ключи

	fmt.Printf("открытый ключ (e, n): %X, %X\n", e, n)
	fmt.Printf("закрытый ключ (d, n): %X, %X\n", d, n)

	fmt.Println("\nШИФРУЕМ")
	encrypted := encrypt(buf, e, n) //шифруем текст открытым ключом
	fmt.Printf("%X\n", encrypted)

	fmt.Println("\nРАСШИФРОВЫВАЕМ")
	fmt.Println(string(decrypt(encrypted, d, n))) //расшифровываем закрытым ключом

	fmt.Println("\nПОДПИСЬ")
	s := sign(hashNum(buf, n), d, n) //шифруем хэш сообщения закрытым ключом
	fmt.Printf("%X\n", s)
	fmt.Println("подлинная подпись:", verify(buf, s, e, n))
	fmt.Println("подпись под измененным текстом:", verify(append(buf, '!'), s, e, n))
}

// чтение ввода
func input() string {
	reader := bufio.NewReader(os.Stdin)  //читаем ввод
	line, err := reader.ReadString('\n') //берем строку с ошибкой чтения
	if err != nil && line == "" {        //если строка пустая и ошибка не пустая, кидаем ошибку
		fmt.Fprintln(os.Stderr, "ошибка чтения строки:", err)
		os.Exit(1)
	}
	return strings.TrimRight(line, "\r\n") //убираем перевод строки
}

// генерация ключей: bits - длина модуля n
func genKeys(bits int) (n, e, d *big.Int) {
	for {
		p, err := rand.Prime(rand.Reader, bits/2) //случайное простое число из bits/2 бит
		check(err)
		q, err := rand.Prime(rand.Reader, bits/2) //второе простое число такой же длины
		check(err)
		if new(big.Int).Abs(new(big.Int).Sub(p, q)).BitLen() < bits/4 { //p и q не должны быть близки друг к другу (заодно отсекает p = q)
			continue
		}

		n = new(big.Int).Mul(p, q) //n = p*q
		pm1 := new(big.Int).Sub(p, big.NewInt(1))
		qm1 := new(big.Int).Sub(q, big.NewInt(1))
		phi := new(big.Int).Mul(pm1, qm1) //функция Эйлера phi(n) = (p-1)(q-1)

		e = randE(phi)     //открытая экспонента
		d = invMod(e, phi) //закрытая экспонента: e*d = 1 (mod phi(n))
		return n, e, d
	}
}

// случайное e (1 < e < phi), взаимно простое с phi
func randE(phi *big.Int) *big.Int {
	for {
		e, err := rand.Int(rand.Reader, phi) //число из диапазона [0, phi)
		check(err)
		if e.Cmp(big.NewInt(1)) > 0 && gcd(e, phi).Cmp(big.NewInt(1)) == 0 { //проверяем взаимную простоту
			return e
		}
	}
}

// наибольший общий делитель, алгоритм Евклида
func gcd(a, b *big.Int) *big.Int {
	a, b = new(big.Int).Set(a), new(big.Int).Set(b) //работаем с копиями, чтобы не испортить аргументы
	for b.Sign() != 0 {
		a, b = b, new(big.Int).Mod(a, b) //пара (a, b) заменяется парой (b, a mod b)
	}
	return a
}

// обратное число по модулю: расширенный алгоритм Евклида, a и m должны быть взаимно просты
func invMod(a, m *big.Int) *big.Int {
	r0, r1 := new(big.Int).Set(m), new(big.Int).Mod(a, m) //остатки, в начале m и a
	t0, t1 := big.NewInt(0), big.NewInt(1)                //коэффициенты при a, всегда t*a = r (mod m)
	for r1.Sign() != 0 {
		k := new(big.Int).Div(r0, r1)                              //частное
		r0, r1 = r1, new(big.Int).Sub(r0, new(big.Int).Mul(k, r1)) //новый остаток
		t0, t1 = t1, new(big.Int).Sub(t0, new(big.Int).Mul(k, t1)) //новый коэффициент
	}
	return t0.Mod(t0, m) //когда остаток стал нулем, в r0 лежит НОД = 1, а в t0 обратное число (может быть отрицательным)
}

// шифрование: текст делится на блоки, блок - число x (0 < x < n), шифруется по формуле y = x^e mod n
func encrypt(text []byte, e, n *big.Int) []*big.Int {
	k := blockLen(n)
	text = pad(text, k) //длина должна быть кратна размеру блока
	out := make([]*big.Int, 0, len(text)/k)
	for i := 0; i < len(text); i += k {
		x := new(big.Int).SetBytes(text[i : i+k]) //блок байт переводим в число
		out = append(out, powMod(x, e, n))        //y = x^e mod n
	}
	return out
}

// расшифрование: каждый блок возводится в степень d, x = y^d mod n
func decrypt(blocks []*big.Int, d, n *big.Int) []byte {
	k := blockLen(n)
	var out []byte
	for _, y := range blocks {
		x := powMod(y, d, n)                               //x = y^d mod n
		out = append(out, x.FillBytes(make([]byte, k))...) //число обратно в k байт, потерянные ведущие нули возвращаются
	}
	return unpad(out, k)
}

// быстрое возведение в степень по модулю: x^e mod n
func powMod(x, e, n *big.Int) *big.Int {
	res := big.NewInt(1)
	b := new(big.Int).Mod(x, n)       //основание, на каждом шаге возводится в квадрат
	for i := 0; i < e.BitLen(); i++ { //идем по битам показателя с младшего
		if e.Bit(i) == 1 { //если бит единица, умножаем результат на текущую степень основания
			res.Mul(res, b).Mod(res, n)
		}
		b.Mul(b, b).Mod(b, n)
	}
	return res
}

// остановка программы при ошибке генератора случайных чисел
func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка генератора случайных чисел:", err)
		os.Exit(1)
	}
}

// размер блока открытого текста в байтах: число из такого количества байт всегда меньше n
func blockLen(n *big.Int) int {
	return (n.BitLen() - 1) / 8
}

// дополнение: байт 0x80, затем нули до конца блока
func pad(text []byte, size int) []byte {
	out := append([]byte{}, text...)
	out = append(out, 0x80)
	for len(out)%size != 0 {
		out = append(out, 0x00)
	}
	return out
}

// снятие дополнения: ищем с конца первый байт 0x80 и отбрасываем хвост
func unpad(text []byte, size int) []byte {
	for i := len(text) - 1; i >= 0 && len(text)-i <= size; i-- {
		if text[i] == 0x80 {
			return text[:i]
		}
		if text[i] != 0x00 { //до 0x80 могут идти только нули
			break
		}
	}
	return text
}

// подпись: хэш шифруется закрытым ключом, s = h^d mod n
func sign(h, d, n *big.Int) *big.Int {
	return powMod(h, d, n)
}

// проверка подписи: h* = s^e mod n должно совпасть с хэшем принятого сообщения
func verify(msg []byte, s, e, n *big.Int) bool {
	if s.Sign() <= 0 || s.Cmp(n) >= 0 { //подпись должна лежать в диапазоне (0, n)
		return false
	}
	return powMod(s, e, n).Cmp(hashNum(msg, n)) == 0
}

// хэш сообщения как число: SHA-256, приводится по модулю n, чтобы выполнялось 0 < h < n
func hashNum(msg []byte, n *big.Int) *big.Int {
	sum := sha256.Sum256(msg)
	h := new(big.Int).SetBytes(sum[:])
	h.Mod(h, n)
	if h.Sign() == 0 { //ноль не подходит
		h.SetInt64(1)
	}
	return h
}

// проверка на примерах из лекций
func selfTest() bool {
	//лекция "Асимметричные криптосистемы": p = 3, q = 11, n = 33, phi(n) = 20, e = 13, сообщение «8275» = блоки 8, 27, 5
	n, e := big.NewInt(33), big.NewInt(13)
	d := invMod(e, big.NewInt(20))
	if d.Int64() != 17 {
		return false
	}
	x := []int64{8, 27, 5}
	y := []int64{17, 15, 26}
	for i := range x {
		c := powMod(big.NewInt(x[i]), e, n)
		if c.Int64() != y[i] || powMod(c, d, n).Int64() != x[i] {
			return false
		}
	}

	//лекция "Алгоритмы хэш-функций и ЭЦП": p = 5, q = 11, n = 55, phi(n) = 40, e = 3, h(M) = 13
	n, e = big.NewInt(55), big.NewInt(3)
	d = invMod(e, big.NewInt(40))
	h := big.NewInt(13)
	s := sign(h, d, n)
	return d.Int64() == 27 && s.Int64() == 7 && powMod(s, e, n).Cmp(h) == 0
}
