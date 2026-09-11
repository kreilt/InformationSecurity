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
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		fmt.Println("Ошибка чтения", err)
		return
	}

	bigrams := splitByTwoRunes(line)

	m1 := randMatrix()
	m2 := randMatrix()

	fmt.Println("Алфавит №1")
	printMatrix(m1)
	fmt.Println("Алфавит №2")
	printMatrix(m2)

	encrypted := handlerCoder(bigrams, m1, m2)
	handlerDecoder(encrypted, m1, m2)
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

func splitByTwoRunes(line string) [][]rune {
	line = replacer.Replace(strings.ToUpper(line))
	rs := []rune(line)
	if len(rs)%2 != 0 {
		rs = append(rs, 'Ъ')
	}
	res := make([][]rune, 0, len(rs)/2)
	for i := 0; i < len(rs); i += 2 {
		res = append(res, rs[i:i+2])
	}
	return res
}

func handlerCoder(bigrams [][]rune, m1, m2 [][]rune) [][]rune {
	fmt.Println("\nШИФРУЕМ")

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
	fmt.Println("\nРАСШИФРОВЫВАЕМ")

	out := make([][]rune, 0, len(bigrams))
	for _, bg := range bigrams {
		c := coder(bg, m2, m1)
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
		out[0], out[1] = m1[i1][j2], m2[i2][j1]
	} else {
		out[0], out[1] = m2[i1][j2], m1[i2][j1]
	}
	return out
}

func printMatrix(m [][]rune) {
	for _, row := range m {
		for _, r := range row {
			if r == ' ' {
				fmt.Print("_ ") // иначе пробел выглядит как потерянная ячейка
			} else {
				fmt.Printf("%c ", r)
			}
		}
		fmt.Println()
	}
	fmt.Println()
}
