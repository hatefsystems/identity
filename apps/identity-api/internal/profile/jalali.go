package profile

/*
Integer-only port of the Borkowski core in jalaali-js v1.2.8, index.js:
https://github.com/jalaali/jalaali-js/tree/f592be0e06867d2752f93924fa3e338f366ce4f4
Go signed / and % preserve upstream truncation toward zero and signed remainder.
The core supports Jalali years -61..3177. Paired conversion also bounds Gregorian
years to 560..3798 so the inverse never calls jalCal with year 3178. Boundary
dates whose other representation is outside those limits fail closed. Day
ordinals are transient calendar arithmetic, not DOB timestamps or stored epochs.

MIT License

Copyright (c) 2020 Behrang Norouzinia

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

type civilDate struct {
	year, month, day int
}

// jalaliCalendar ports jalCal, sharing its leap calculation with validation.
func jalaliCalendar(year int) (march, leap int, ok bool) {
	breaks := [...]int{-61, 9, 38, 199, 426, 686, 756, 818, 1111, 1181, 1210, 1635, 2060, 2097, 2192, 2262, 2324, 2394, 2456, 3178}
	if year < breaks[0] || year >= breaks[len(breaks)-1] {
		return 0, 0, false
	}
	gy, leapJ, jp, jump := year+621, -14, breaks[0], 0
	for _, jm := range breaks[1:] {
		jump = jm - jp
		if year < jm {
			break
		}
		leapJ += jump/33*8 + (jump%33)/4
		jp = jm
	}
	n := year - jp
	leapJ += n/33*8 + (n%33+3)/4
	if jump%33 == 4 && jump-n == 4 {
		leapJ++
	}
	leapG := gy/4 - ((gy/100+1)*3)/4 - 150
	march = 20 + leapJ - leapG
	if jump-n < 6 {
		n = n - jump + (jump+4)/33*33
	}
	leap = ((n+1)%33 - 1) % 4
	if leap == -1 {
		leap = 4
	}
	return march, leap, true
}

func gregorianMonthDays(year, month int) int {
	switch month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	default:
		return 0
	}
}

func validGregorian(date civilDate) bool {
	return date.year >= 560 && date.year <= 3798 && date.day >= 1 && date.day <= gregorianMonthDays(date.year, date.month)
}

func validJalali(date civilDate) bool {
	_, leap, ok := jalaliCalendar(date.year)
	if !ok || date.month < 1 || date.month > 12 || date.day < 1 {
		return false
	}
	days := 30
	if date.month <= 6 {
		days = 31
	} else if date.month == 12 && leap != 0 {
		days = 29
	}
	return date.day <= days
}

// Callers validate civil components and bounds before ordinal arithmetic.
func gregorianDay(date civilDate) int {
	year, month := date.year, date.month
	d := (year+(month-8)/6+100100)*1461/4 + (153*((month+9)%12)+2)/5 + date.day - 34840408
	return d - ((year+100100+(month-8)/6)/100*3)/4 + 752
}

func dayGregorian(day int) civilDate {
	j := 4*day + 139361631
	j += ((4*day+183187720)/146097*3)/4*4 - 3908
	i := (j%1461)/4*5 + 308
	gd := (i%153)/5 + 1
	gm := (i/153)%12 + 1
	gy := j/1461 - 100100 + (8-gm)/6
	return civilDate{gy, gm, gd}
}

func jalaliDay(date civilDate, march int) int {
	return gregorianDay(civilDate{date.year + 621, 3, march}) + (date.month-1)*31 - date.month/7*(date.month-7) + date.day - 1
}

func gregorianToJalali(date civilDate) (civilDate, bool) {
	if !validGregorian(date) {
		return civilDate{}, false
	}
	year := date.year - 621
	march, leap, ok := jalaliCalendar(year)
	if !ok {
		return civilDate{}, false
	}
	k := gregorianDay(date) - gregorianDay(civilDate{date.year, 3, march})
	var result civilDate
	if k >= 0 && k <= 185 {
		result = civilDate{year, 1 + k/31, k%31 + 1}
	} else {
		if k >= 0 {
			k -= 186
		} else {
			year--
			k += 179
			if leap == 1 {
				k++
			}
		}
		result = civilDate{year, 7 + k/30, k%30 + 1}
	}
	if !validJalali(result) {
		return civilDate{}, false
	}
	return result, true
}

func jalaliToGregorian(date civilDate) (civilDate, bool) {
	if !validJalali(date) {
		return civilDate{}, false
	}
	march, _, _ := jalaliCalendar(date.year)
	result := dayGregorian(jalaliDay(date, march))
	if !validGregorian(result) {
		return civilDate{}, false
	}
	return result, true
}
