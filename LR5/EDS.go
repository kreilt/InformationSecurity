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

// точка эллиптической кривой
type point struct {
	x, y *big.Int
	inf  bool //бесконечно удаленная точка, нулевой элемент группы
}

// параметры эллиптической кривой y^2 = x^3 + a*x + b (mod p): тестовый пример из ГОСТ Р 34.10-2012 (256 бит)
// curveP - модуль поля p, curveA и curveB - коэффициенты a и b,
// orderQ - порядок циклической подгруппы q, baseP - базовая точка подгруппы P
var (
	curveP = hexNum("8000000000000000000000000000000000000000000000000000000000000431")
	curveA = big.NewInt(7)
	curveB = hexNum("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E")
	orderQ = hexNum("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3")
	baseP  = point{x: big.NewInt(2), y: hexNum("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8")}
)

func main() {
	if !selfTest() { //сверяем механизм с контрольным примером из ГОСТ
		fmt.Fprintln(os.Stderr, "ошибка механизма шифрования")
		os.Exit(1)
	}

	buf := input()      //читаем инпут
	d, pub := genKeys() //генерируем ключ подписи d и ключ проверки Q = dP

	fmt.Printf("d: %X\n", d)
	fmt.Printf("Q: x = %X\n   y = %X\n", pub.x, pub.y)

	fmt.Println("\nПОДПИСЫВАЕМ")
	e := hashNum([]byte(buf)) //хэш сообщения как число
	r, s := sign(e, d)        //формируем подпись (r, s)
	fmt.Printf("h: %X\n", e)
	fmt.Printf("r: %X\n", r)
	fmt.Printf("s: %X\n", s)
	r2, s2 := sign(e, d) //из-за случайного k подпись одного и того же сообщения каждый раз разная
	fmt.Println("вторая подпись отличается от первой:", r.Cmp(r2) != 0 || s.Cmp(s2) != 0)

	fmt.Println("\nПРОВЕРЯЕМ ПОДПИСЬ")
	fmt.Println("подлинная подпись:", verify(e, r, s, pub))
	fmt.Println("подделанная подпись:", verify(e, r, new(big.Int).Add(s, big.NewInt(1)), pub))
	fmt.Println("подпись под измененным текстом:", verify(hashNum([]byte(buf+"!")), r, s, pub))
	_, otherPub := genKeys() //чужой ключ проверки
	fmt.Println("проверка чужим ключом:", verify(e, r, s, otherPub))
}

// число из шестнадцатеричной строки
func hexNum(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		fmt.Fprintln(os.Stderr, "ошибка параметров кривой")
		os.Exit(1)
	}
	return v
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

// генерация ключей: d - ключ подписи (0 < d < q), Q = dP - ключ проверки
func genKeys() (*big.Int, point) {
	d := randScalar()
	return d, mul(d, baseP)
}

// случайное число из диапазона [1, q-1]
func randScalar() *big.Int {
	v, err := rand.Int(rand.Reader, new(big.Int).Sub(orderQ, big.NewInt(1))) //crypto/rand берет энтропию у операционной системы
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка генератора случайных чисел:", err)
		os.Exit(1)
	}
	return v.Add(v, big.NewInt(1)) //сдвигаем диапазон [0, q-2] в [1, q-1]
}

// кратная точка kP = P + P + ... + P: двоичное разложение k, от старшего бита к младшему
func mul(k *big.Int, pt point) point {
	res := point{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		res = add(res, res) //удваиваем
		if k.Bit(i) == 1 {
			res = add(res, pt) //если бит единица, прибавляем точку
		}
	}
	return res
}

// сумма двух точек кривой
func add(p1, p2 point) point {
	if p1.inf { //нулевой элемент не меняет сумму
		return p2
	}
	if p2.inf {
		return p1
	}

	var lambda *big.Int
	if p1.x.Cmp(p2.x) == 0 {
		if p1.y.Cmp(p2.y) != 0 || p1.y.Sign() == 0 { //точки противоположны, их сумма - бесконечно удаленная точка
			return point{inf: true}
		}
		//удвоение точки: lambda = (3*x^2 + a) / (2*y) mod p
		num := new(big.Int).Mul(p1.x, p1.x)
		num.Mul(num, big.NewInt(3)).Add(num, curveA).Mod(num, curveP)
		den := new(big.Int).Lsh(p1.y, 1)
		den.Mod(den, curveP)
		lambda = num.Mul(num, new(big.Int).ModInverse(den, curveP)) //деление - умножение на обратное по модулю p
	} else {
		//сложение разных точек: lambda = (y2 - y1) / (x2 - x1) mod p
		num := new(big.Int).Sub(p2.y, p1.y)
		num.Mod(num, curveP)
		den := new(big.Int).Sub(p2.x, p1.x)
		den.Mod(den, curveP)
		lambda = num.Mul(num, new(big.Int).ModInverse(den, curveP))
	}
	lambda.Mod(lambda, curveP)

	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, p1.x).Sub(x3, p2.x).Mod(x3, curveP) //x3 = lambda^2 - x1 - x2 (mod p)
	y3 := new(big.Int).Sub(p1.x, x3)
	y3.Mul(y3, lambda).Sub(y3, p1.y).Mod(y3, curveP) //y3 = lambda*(x1 - x3) - y1 (mod p)
	return point{x: x3, y: y3}
}

// хэш сообщения как число: e = alpha mod q, где alpha - двоичное представление хэш-кода (вместо Стрибога SHA-256)
func hashNum(msg []byte) *big.Int {
	sum := sha256.Sum256(msg)
	e := new(big.Int).SetBytes(sum[:])
	e.Mod(e, orderQ)
	if e.Sign() == 0 { //если alpha mod q = 0, то e принимается за 1
		e.SetInt64(1)
	}
	return e
}

// формирование подписи (r, s)
func sign(e, d *big.Int) (*big.Int, *big.Int) {
	for {
		k := randScalar()                   //случайное одноразовое число k, 0 < k < q
		r, s := signK(e, d, k)              //считаем подпись
		if r.Sign() != 0 && s.Sign() != 0 { //если r или s равно 0, возвращаемся к выбору k
			return r, s
		}
	}
}

// подпись при заданном k: C = kP, r = xc mod q, s = (r*d + k*e) mod q
func signK(e, d, k *big.Int) (r, s *big.Int) {
	c := mul(k, baseP) //точка C = kP
	r = new(big.Int).Mod(c.x, orderQ)
	s = new(big.Int).Mul(r, d)
	s.Add(s, new(big.Int).Mul(k, e)).Mod(s, orderQ)
	return r, s
}

// проверка подписи (r, s) ключом проверки Q
func verify(e, r, s *big.Int, pub point) bool {
	if r.Sign() <= 0 || r.Cmp(orderQ) >= 0 || s.Sign() <= 0 || s.Cmp(orderQ) >= 0 { //первичная проверка: 0 < r < q и 0 < s < q
		return false
	}
	v := new(big.Int).ModInverse(e, orderQ) //v = e^-1 mod q
	z1 := new(big.Int).Mul(s, v)
	z1.Mod(z1, orderQ) //z1 = s*v mod q
	z2 := new(big.Int).Mul(r, v)
	z2.Neg(z2).Mod(z2, orderQ)             //z2 = -r*v mod q
	c := add(mul(z1, baseP), mul(z2, pub)) //точка C = z1*P + z2*Q
	if c.inf {
		return false
	}
	return new(big.Int).Mod(c.x, orderQ).Cmp(r) == 0 //R = xc mod q, подпись верна, если R = r
}

// проверка на контрольном примере из ГОСТ Р 34.10-2012
func selfTest() bool {
	if !onCurve(baseP) || !mul(orderQ, baseP).inf { //P лежит на кривой и порядок точки равен q: qP = O
		return false
	}

	d := hexNum("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28") //ключ подписи
	e := hexNum("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5") //хэш сообщения
	k := hexNum("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3") //случайное число
	wantQ := point{                                                                 //ключ проверки Q = dP
		x: hexNum("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B"),
		y: hexNum("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA"),
	}
	r := hexNum("41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493") //ожидаемая подпись
	s := hexNum("01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40")

	pub := mul(d, baseP)
	if pub.x.Cmp(wantQ.x) != 0 || pub.y.Cmp(wantQ.y) != 0 { //dP должно совпасть с Q из примера
		return false
	}
	gotR, gotS := signK(e, d, k)
	return gotR.Cmp(r) == 0 && gotS.Cmp(s) == 0 && verify(e, r, s, wantQ)
}

// лежит ли точка на кривой: y^2 = x^3 + a*x + b (mod p)
func onCurve(pt point) bool {
	left := new(big.Int).Mul(pt.y, pt.y)
	left.Mod(left, curveP)
	right := new(big.Int).Mul(pt.x, pt.x)
	right.Mul(right, pt.x)
	right.Add(right, new(big.Int).Mul(curveA, pt.x))
	right.Add(right, curveB).Mod(right, curveP)
	return left.Cmp(right) == 0
}
