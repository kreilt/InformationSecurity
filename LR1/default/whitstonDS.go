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

// замена невалидных символов
var replacer = strings.NewReplacer(
	"Ё", "Е", //замена Ё на Е
	"Й", "И", //Й на И и так далее
	"\t", " ",
	"\r", "",
	"\n", "",
)

func main() {
	bigrams := splitByTwoRunes(input()) //принимает строку и сразу делим ее на биграммы

	m1 := randMatrix() //создаем 2 рандомных алфавита
	m2 := randMatrix()
	//m1, m2 = refMatrices() //алфавиты из презентации
	printMatrices(m1, m2) //выводим алфавиты

	fmt.Println("\nШИФРУЕМ")
	encrypted := handlerCoder(bigrams, m1, m2) //шифруем биграммы

	fmt.Println("\nРАСШИФРОВЫВАЕМ")
	handlerCoder(encrypted, m2, m1) //расшифровываем биграммы той же функцией, отправляя туда зашифрованный текст
}

// чтение ввода
func input() string {
	reader := bufio.NewReader(os.Stdin)  // читаем ввод
	line, err := reader.ReadString('\n') //берем строку с ошибку чтения
	if err != nil && line == "" {        //если строка пустая или ошибка не пустая, кидаем ошибку
		fmt.Fprintf(os.Stderr, "ошибка чтения строки: %v\n", err)
	}
	return line
}

// разделение строки на руны
func splitByTwoRunes(line string) [][]rune {
	line = replacer.Replace(strings.ToUpper(line)) //преобразуем строку в единный формат
	rs := []rune(line)                             //приводим к типу []rune
	if len(rs)%2 != 0 {                            //если длина нечетная добавляем пробел в конец
		rs = append(rs, ' ')
	}
	res := make([][]rune, 0, len(rs)/2)
	for i := 0; i < len(rs); i += 2 { //идем по строке и заполняем массив рун
		res = append(res, rs[i:i+2])
	}
	return res
}

// рандомная матрица по алфавиту
func randMatrix() [][]rune {
	a := []rune(alphabet)    //преобразуем алфавит в []rune
	if len(a) != rows*cols { //проверяем размерность
		panic("Неверное количество символов в алфавите")
	}

	rand.Shuffle(len(a), func(i, j int) { //перемешиваем алфавит с помощью свапа каждого символа с рандомным
		a[i], a[j] = a[j], a[i]
	})

	m := make([][]rune, rows) //создаем матрицу
	for i := range m {
		m[i] = make([]rune, cols)
		copy(m[i], a[i*cols:(i+1)*cols]) //копируем символ из алфавита в матрицу
	}

	return m
}

// обработчик шифровщика
func handlerCoder(bigrams [][]rune, m1, m2 [][]rune) [][]rune {

	out := make([][]rune, 0, len(bigrams))
	for _, bg := range bigrams { //берем каждую биграмму
		c := coder(bg, m1, m2)       //отправляем в коде
		out = append(out, c)         //добавляем в результирующий массив
		fmt.Printf("%q ", string(c)) //выводим
	}
	fmt.Println()
	return out
}

// кодер рун
func coder(bigram []rune, m1, m2 [][]rune) []rune {
	var i1, j1 int = -1, -1 //объясвляем переменные для памяти позиций
	var i2, j2 int = -1, -1
	out := make([]rune, 2)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			if bigram[0] == m1[i][j] { //ищем 1 символ биграммы в 1 алфавите
				i1 = i //запоминаем позиции
				j1 = j
			}
			if bigram[1] == m2[i][j] { //ищем 2 символ биграммы во 2 алфавите
				i2 = i //запоминаем позиции
				j2 = j
			}
		}
	}
	if i1 == -1 || i2 == -1 || j1 == -1 || j2 == -1 { //проверяем заполнена ли память
		fmt.Fprintln(os.Stderr, "Проблема шифрования: символа нет в алфавите")
		os.Exit(1)
	}
	out[0], out[1] = m2[i1][j2], m1[i2][j1] // буквы шифртекста — две оставшиеся вершины мнимого прямоугольника
	return out
}

// принт матриц-алфавитов
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

// принт строки
func printRow(row []rune) {
	for _, r := range row {
		if r == ' ' {
			fmt.Print("_ ")
		} else {
			fmt.Printf("%c ", r)
		}
	}
}

// матрицы из презентации
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
