package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
)

const (
	rows     = 7
	cols     = 5
	alphabet = "АБВГДЕЖЗИКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ.,: "
)

var replacer = strings.NewReplacer(
	"Ё", "Е",
	"Й", "И",
	"\t", " ",
	"\r", "",
	"\n", "",
)

func main() {
	bigrams := splitByTwoRunes(input())

	m1 := randMatrix()
	m2 := randMatrix()
	//m1, m2 = refMatrices()
	printMatrices(m1, m2)

	fmt.Println("\nШИФРУЕМ")
	encrypted := handlerCoder(bigrams, m1, m2)

	fmt.Println("\nРАСШИФРОВЫВАЕМ")
	handlerDecoder(encrypted, m1, m2)
}

func input() string {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintf(os.Stderr, "ошибка чтения строки: %v\n", err)
	}
	return line
}

func splitByTwoRunes(line string) [][]rune {
	line = replacer.Replace(strings.ToUpper(line))
	rs := []rune(line)
	if len(rs)%2 != 0 {
		rs = append(rs, ' ')
	}
	res := make([][]rune, 0, len(rs)/2)
	for i := 0; i < len(rs); i += 2 {
		res = append(res, rs[i:i+2])
	}
	return res
}

func randMatrix() [][]rune {
	a := []rune(alphabet)
	if len(a) != rows*cols {
		panic("Неверное количество симовлов в алфавите")
	}

	rand.Shuffle(len(a), func(i, j int) {
		a[i], a[j] = a[j], a[i]
	})

	m := make([][]rune, rows)
	for i := range m {
		m[i] = make([]rune, cols)
		copy(m[i], a[i*cols:(i+1)*cols])
	}

	return m
}

func handlerCoder(bigrams [][]rune, m1, m2 [][]rune) [][]rune {

	out := make([][]rune, 0, len(bigrams))
	for _, bg := range bigrams {
		c := coder(bg, m1, m2)
		out = append(out, c)
		fmt.Printf("%q ", string(c))
	}
	fmt.Println()
	return out
}

func handlerDecoder(bigrams [][]rune, m1, m2 [][]rune) [][]rune {

	out := make([][]rune, 0, len(bigrams))
	for _, bg := range bigrams {
		c := decoder(bg, m1, m2)
		out = append(out, c)
		fmt.Printf("%q ", string(c))
	}
	fmt.Println()
	return out
}

func coder(bigram []rune, m1, m2 [][]rune) []rune {
	var i1, j1 int = -1, -1
	var i2, j2 int = -1, -1
	out := make([]rune, 2)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			if bigram[0] == m1[i][j] {
				i1 = i
				j1 = j
			}
			if bigram[1] == m2[i][j] {
				i2 = i
				j2 = j
			}
		}
	}
	if i1 == -1 || i2 == -1 || j1 == -1 || j2 == -1 {
		panic("Проблема шифрования")
	}
	if i1 == i2 {
		out[0], out[1] = m2[i1][(j1+1)%cols], m1[i2][(j2+1)%cols]
	} else {
		out[0], out[1] = m2[i1][j2], m1[i2][j1]
	}
	return out
}

func decoder(bigram []rune, m1, m2 [][]rune) []rune {
	var i1, j1 int = -1, -1
	var i2, j2 int = -1, -1
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			if bigram[0] == m2[i][j] {
				i1 = i
				j1 = j
			}
			if bigram[1] == m1[i][j] {
				i2 = i
				j2 = j
			}
		}
	}
	if i1 == -1 || i2 == -1 {
		panic("Проблема расшифрования")
	}

	out := make([]rune, 2)
	if i1 == i2 {
		out[0], out[1] = m1[i1][(j1-1+cols)%cols], m2[i2][(j2-1+cols)%cols]
	} else {
		out[0], out[1] = m1[i1][j2], m2[i2][j1]
	}
	return out
}

func printMatrices(m1, m2 [][]rune) {
	fmt.Println("   Алфавит №1     Алфавит №2")
	for i := 0; i < rows; i++ {
		fmt.Print("   ")
		printRow(m1[i])
		fmt.Print("     ")
		printRow(m2[i])
		fmt.Println()
	}
	fmt.Println()
}

func printRow(row []rune) {
	for _, r := range row {
		if r == ' ' {
			fmt.Print("_ ")
		} else {
			fmt.Printf("%c ", r)
		}
	}
}

func refMatrices() ([][]rune, [][]rune) {
	parse := func(rowsStr []string) [][]rune {
		m := make([][]rune, rows)
		for i, s := range rowsStr {
			m[i] = []rune(s)
		}
		return m
	}
	left := parse([]string{
		"ЖЩНЮР",
		"ИТЬЦБ",
		"ЯМЕ.С",
		"ВЫПЧ ",
		":ДУОК",
		"ЗЭФГШ",
		"ХА,ЛЪ",
	})
	right := parse([]string{
		"ИЧГЯТ",
		",ЖЬМО",
		"ЗЮРВЩ",
		"Ц:ПЕЛ",
		"ЪАН.Х",
		"ЭКСШД",
		"БФУЫ ",
	})
	return left, right
}
