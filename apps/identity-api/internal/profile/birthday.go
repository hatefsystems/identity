package profile

import (
	"errors"
	"fmt"
	"sync"
	"time"
	_ "time/tzdata" // Keep Asia/Tehran available in stripped runtime images.
	"unicode/utf8"
)

// Birthday is one equivalent pair of canonical ASCII date-only values.
type Birthday struct {
	Gregorian string
	Jalali    string
}

// Birthday errors are static and never include rejected private values.
var (
	ErrInvalidBirthday   = errors.New("profile: invalid birthday")
	ErrBirthdayClock     = errors.New("profile: birthday clock unavailable")
	loadBirthdayLocation = sync.OnceValues(func() (*time.Location, error) { return time.LoadLocation("Asia/Tehran") })
)

// NormalizeBirthday validates an explicit calendar and date against one trusted
// server clock sample. DOB arithmetic never constructs an instant or duration.
func NormalizeBirthday(calendar, date string, now time.Time) (Birthday, error) {
	if calendar != "gregorian" && calendar != "jalali" {
		return Birthday{}, ErrInvalidBirthday
	}
	input, ok := parseBirthdayDate(date)
	if !ok {
		return Birthday{}, ErrInvalidBirthday
	}
	location, err := loadBirthdayLocation()
	if err != nil || location == nil || now.IsZero() {
		return Birthday{}, ErrBirthdayClock
	}
	year, month, day := now.In(location).Date()
	if year < 1900 || year > 9999 {
		return Birthday{}, ErrBirthdayClock
	}
	today := civilDate{year, int(month), day}
	var gregorian, jalali civilDate
	if calendar == "gregorian" {
		gregorian = input
		jalali, ok = gregorianToJalali(input)
		if ok {
			var roundTrip civilDate
			roundTrip, ok = jalaliToGregorian(jalali)
			ok = ok && roundTrip == input
		}
	} else {
		jalali = input
		gregorian, ok = jalaliToGregorian(input)
		if ok {
			var roundTrip civilDate
			roundTrip, ok = gregorianToJalali(gregorian)
			ok = ok && roundTrip == input
		}
	}
	if !ok || gregorian.year < 1900 || civilAfter(gregorian, today) {
		return Birthday{}, ErrInvalidBirthday
	}
	return Birthday{Gregorian: formatCivil(gregorian), Jalali: formatCivil(jalali)}, nil
}

func parseBirthdayDate(raw string) (civilDate, bool) {
	if len(raw) > 18 || !utf8.ValidString(raw) {
		return civilDate{}, false
	}
	var components [3]int
	index, part := 0, 0
	for _, r := range raw {
		if index >= 10 {
			return civilDate{}, false
		}
		if index == 4 || index == 7 {
			if r != '-' {
				return civilDate{}, false
			}
			part++
		} else {
			switch {
			case r >= '0' && r <= '9':
				r -= '0'
			case r >= '\u06f0' && r <= '\u06f9':
				r -= '\u06f0'
			case r >= '\u0660' && r <= '\u0669':
				r -= '\u0660'
			default:
				return civilDate{}, false
			}
			components[part] = components[part]*10 + int(r)
		}
		index++
	}
	if index != 10 {
		return civilDate{}, false
	}
	return civilDate{components[0], components[1], components[2]}, true
}

func civilAfter(left, right civilDate) bool {
	if left.year != right.year {
		return left.year > right.year
	}
	if left.month != right.month {
		return left.month > right.month
	}
	return left.day > right.day
}

func formatCivil(date civilDate) string {
	return fmt.Sprintf("%04d-%02d-%02d", date.year, date.month, date.day)
}
