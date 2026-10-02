package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
)

const (
	blockSize = 16 //длина блока 128 бит
	rounds    = 10 //число раундовых ключей
	poly      = 0x1C3
)

// нелинейное биективное преобразование: подстановка pi из ГОСТ Р 34.12-2015
var pi = [256]byte{
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
	249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
	5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
	235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
	181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
	21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
	223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
	167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
	7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
	225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
	32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
	89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
}

// обратная подстановка, строится из pi при запуске
var piInv [256]byte

// коэффициенты линейного преобразования, старший байт первым
var lCoef = [16]byte{148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1}

func init() {
	for i, v := range pi { //обратная подстановка: на место значения ставим его индекс
		piInv[v] = byte(i)
	}
}

func main() {
	if !selfTest() { //сверяем шифр с контрольным примером из ГОСТ
		fmt.Fprintln(os.Stderr, "ошибка механизма шифрования")
		os.Exit(1)
	}

	buf := input()            //читаем инпут
	key := rand256()          //генерируем ключ 256 бит
	keys := genRoundKeys(key) //разворачиваем ключ в 10 раундовых по 128 бит

	fmt.Printf("KEY: %X\n", key)

	fmt.Println("\nШИФРУЕМ")
	encrypted := ecbEncrypt([]byte(buf), keys) //шифруем текст в режиме простой замены
	fmt.Printf("% X\n", encrypted)             //выводим в шестнадцатеричном виде, так как шифртекст - байты

	fmt.Println("\nРАСШИФРОВЫВАЕМ")
	decrypted := ecbDecrypt(encrypted, keys) //расшифровываем тем же ключом
	fmt.Println(string(decrypted))
}

// генератор случайного ключа в 256 бит
func rand256() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil { //crypto/rand берет энтропию у операционной системы
		fmt.Fprintln(os.Stderr, "ошибка генератора случайных чисел:", err)
		os.Exit(1)
	}
	return b
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

// умножение в поле Галуа GF(2^8) по модулю x^8+x^7+x^6+x+1
func gmul(a, b byte) byte {
	var r byte
	for b != 0 {
		if b&1 != 0 { //если младший бит множителя единица, добавляем текущее значение
			r ^= a
		}
		b >>= 1
		hi := a&0x80 != 0 //запоминаем, уйдет ли старший бит за границу байта
		a <<= 1
		if hi { //если ушел, приводим по модулю неприводимого многочлена
			a ^= poly & 0xFF
		}
	}
	return r
}

// нелинейное преобразование S: каждый байт блока заменяется по подстановке
func s(v [blockSize]byte) [blockSize]byte {
	for i := range v {
		v[i] = pi[v[i]]
	}
	return v
}

// обратное нелинейное преобразование
func sInv(v [blockSize]byte) [blockSize]byte {
	for i := range v {
		v[i] = piInv[v[i]]
	}
	return v
}

// свертка блока в один байт: сумма произведений байтов на коэффициенты
func ell(v [blockSize]byte) byte {
	var r byte
	for i := range v {
		r ^= gmul(v[i], lCoef[i])
	}
	return r
}

// шаг линейного преобразования R: сдвиг блока вправо, слева дописывается свертка
func rStep(v [blockSize]byte) [blockSize]byte {
	e := ell(v)
	copy(v[1:], v[:blockSize-1])
	v[0] = e
	return v
}

// обратный шаг: сдвиг влево, справа восстанавливается потерянный байт
func rStepInv(v [blockSize]byte) [blockSize]byte {
	first := v[0] //это была свертка исходного блока
	copy(v[:blockSize-1], v[1:])
	v[blockSize-1] = 0
	//последний коэффициент равен единице, поэтому байт находится одним XOR
	v[blockSize-1] = ell(v) ^ first
	return v
}

// линейное преобразование L: шаг R, повторенный 16 раз
func l(v [blockSize]byte) [blockSize]byte {
	for i := 0; i < blockSize; i++ {
		v = rStep(v)
	}
	return v
}

// обратное линейное преобразование
func lInv(v [blockSize]byte) [blockSize]byte {
	for i := 0; i < blockSize; i++ {
		v = rStepInv(v)
	}
	return v
}

// сложение блоков по модулю 2
func xor(a, b [blockSize]byte) [blockSize]byte {
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

// развертка ключа: из 256 бит получаем 10 раундовых ключей по 128 бит
func genRoundKeys(key []byte) [rounds][blockSize]byte {
	var keys [rounds][blockSize]byte
	copy(keys[0][:], key[:blockSize]) //первый раундовый ключ - левая половина
	copy(keys[1][:], key[blockSize:]) //второй - правая половина
	a, b := keys[0], keys[1]

	n := 2
	for i := 1; i <= 32; i++ {
		var c [blockSize]byte
		c[blockSize-1] = byte(i) //номер итерации как 128-битное число
		c = l(c)                 //константа C_i получается линейным преобразованием номера

		a, b = xor(l(s(xor(a, c))), b), a //преобразование Фейстеля
		if i%8 == 0 {                     //каждые восемь итераций снимаем пару ключей
			keys[n], keys[n+1] = a, b
			n += 2
		}
	}
	return keys
}

// зашифрование одного блока в 128 бит
func encryptBlock(v [blockSize]byte, keys [rounds][blockSize]byte) [blockSize]byte {
	for i := 0; i < rounds-1; i++ { //девять раундов: сложение с ключом, подстановка, линейное преобразование
		v = l(s(xor(v, keys[i])))
	}
	return xor(v, keys[rounds-1]) //десятый раунд только складывается с ключом
}

// расшифрование одного блока: те же шаги в обратном порядке
func decryptBlock(v [blockSize]byte, keys [rounds][blockSize]byte) [blockSize]byte {
	v = xor(v, keys[rounds-1])
	for i := rounds - 2; i >= 0; i-- {
		v = xor(sInv(lInv(v)), keys[i])
	}
	return v
}

// дополнение по ГОСТ Р 34.13-2015: байт 0x80, затем нули до конца блока
func pad(text []byte) []byte {
	out := append([]byte{}, text...)
	out = append(out, 0x80)
	for len(out)%blockSize != 0 {
		out = append(out, 0x00)
	}
	return out
}

// снятие дополнения: ищем с конца первый байт 0x80 и отбрасываем хвост
func unpad(text []byte) []byte {
	for i := len(text) - 1; i >= 0 && len(text)-i <= blockSize; i-- {
		if text[i] == 0x80 {
			return text[:i]
		}
		if text[i] != 0x00 { //до 0x80 могут идти только нули
			break
		}
	}
	return text
}

// режим простой замены: блоки шифруются независимо друг от друга
func ecbEncrypt(text []byte, keys [rounds][blockSize]byte) []byte {
	text = pad(text) //длина должна быть кратна размеру блока
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i += blockSize {
		var v [blockSize]byte
		copy(v[:], text[i:i+blockSize])
		e := encryptBlock(v, keys)
		out = append(out, e[:]...)
	}
	return out
}

// расшифрование в режиме простой замены
func ecbDecrypt(text []byte, keys [rounds][blockSize]byte) []byte {
	out := make([]byte, 0, len(text))
	for i := 0; i+blockSize <= len(text); i += blockSize {
		var v [blockSize]byte
		copy(v[:], text[i:i+blockSize])
		d := decryptBlock(v, keys)
		out = append(out, d[:]...)
	}
	return unpad(out)
}

// проверка на контрольном примере из ГОСТ Р 34.12-2015
func selfTest() bool {
	key := []byte{
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	pt := [blockSize]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	want := [blockSize]byte{0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
		0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd}

	keys := genRoundKeys(key)
	return encryptBlock(pt, keys) == want && decryptBlock(want, keys) == pt
}
