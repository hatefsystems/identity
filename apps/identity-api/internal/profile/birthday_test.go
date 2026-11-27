package profile

import (
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// All time.Time values in these tests are trusted clock samples, never DOBs.
func birthdayTestClock() time.Time {
	return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
}

func TestBirthdayReferenceVectors(t *testing.T) {
	for _, tc := range []struct{ source, gregorian, jalali string }{
		// Port-fidelity vectors: pinned upstream test.js, not independent evidence.
		{"upstream", "1981-08-17", "1360-05-26"},
		{"upstream", "2013-01-10", "1391-10-21"},
		{"upstream", "2014-08-04", "1393-05-13"},
		// Independent authority-table transcription (year-start rows and leap flags):
		// https://github.com/roozbehp/persiancalendar/blob/63562e04042fd9735b0aaa555719830311c6981d/kabise.txt
		// Original University of Tehran PDF was not accessible during review; these
		// fixed rows are also reproduced in ICU PersianTest.java at revision
		// 8e0e87c31f34cb9ee028e6487f5199dc607e0f59. Leap-end companions follow from
		// the published leap flags and next year's first day, not this converter.
		{"authority", "1900-03-21", "1279-01-01"},
		{"authority", "2000-03-20", "1379-01-01"},
		{"authority", "2016-03-20", "1395-01-01"},
		{"authority leap end", "2017-03-20", "1395-12-30"},
		{"authority", "2017-03-21", "1396-01-01"},
		{"authority", "2020-03-20", "1399-01-01"},
		{"authority leap end", "2021-03-20", "1399-12-30"},
		{"authority", "2021-03-21", "1400-01-01"},
		{"authority", "2024-03-20", "1403-01-01"},
		// ICU fixed Rata Die 739330 / 739331 independently corroborates this boundary:
		// https://github.com/unicode-org/icu/blob/8e0e87c31f34cb9ee028e6487f5199dc607e0f59/icu4j/main/core/src/test/java/com/ibm/icu/dev/test/calendar/PersianTest.java
		{"ICU leap end", "2025-03-20", "1403-12-30"},
		{"authority and ICU", "2025-03-21", "1404-01-01"},
	} {
		t.Run(tc.source+" "+tc.gregorian, func(t *testing.T) {
			want := Birthday{Gregorian: tc.gregorian, Jalali: tc.jalali}
			for _, calendar := range []string{"gregorian", "jalali"} {
				input := tc.gregorian
				if calendar == "jalali" {
					input = tc.jalali
				}
				got, err := NormalizeBirthday(calendar, input, birthdayTestClock())
				if err != nil || got != want {
					t.Fatal("reference vector mismatch")
				}
				assertBirthdayInvariant(t, got, err, birthdayTestClock())
			}
		})
	}
}

func TestBirthdayDigitGrammar(t *testing.T) {
	for _, calendar := range []string{"gregorian", "jalali"} {
		ascii := "2000-01-09"
		if calendar == "jalali" {
			ascii = "1379-01-09"
		}
		want, err := NormalizeBirthday(calendar, ascii, birthdayTestClock())
		if err != nil {
			t.Fatal("synthetic grammar fixture rejected")
		}
		// Every choice of admitted script at each of eight digit positions.
		for mixture := 0; mixture < 6561; mixture++ {
			choice := mixture
			var raw strings.Builder
			for _, r := range ascii {
				if r != '-' {
					base := [...]rune{'0', '\u06f0', '\u0660'}[choice%3]
					r = base + r - '0'
					choice /= 3
				}
				raw.WriteRune(r)
			}
			got, err := NormalizeBirthday(calendar, raw.String(), birthdayTestClock())
			if err != nil || got != want {
				t.Fatal("admitted digit mixture changed civil date")
			}
			if mixture == 3280 && raw.Len() != 18 {
				t.Fatal("maximum admitted byte boundary not exercised")
			}
			assertBirthdayInvariant(t, got, err, birthdayTestClock())
		}
	}
	for _, calendar := range []string{"", "gregory", "persian", "Gregorian", "JALALI", "gregorian ", "fa-IR", "\xff", strings.Repeat("x", 100000)} {
		got, err := NormalizeBirthday(calendar, "2000-01-01", birthdayTestClock())
		if err != ErrInvalidBirthday {
			t.Fatal("unsupported calendar accepted")
		}
		assertBirthdayInvariant(t, got, err, birthdayTestClock())
	}
	for _, raw := range []string{
		"", "2000-1-01", "2000-01-1", "02000-01-01", "2000-001-01", "2000-01-001", "200-01-01",
		"+2000-01-01", "-2000-01-01", "2000/01/01", "2000.01.01", "2000-01-01T00:00:00Z",
		" 2000-01-01", "2000-01-01 ", "2000-01-01\n", "2000-01-01\x00", "2000-\xff1-01",
		"\uff12\uff10\uff10\uff10-01-01", "\u0968\u0966\u0966\u0966-01-01", "\u00b22000-01-01",
		"\u06f2\u06f0\u06f0\u06f0-\u06f0\u06f1-\u06f0\u06f1x", strings.Repeat("x", 100000),
	} {
		for _, calendar := range []string{"gregorian", "jalali"} {
			got, err := NormalizeBirthday(calendar, raw, birthdayTestClock())
			if err != ErrInvalidBirthday {
				t.Fatal("invalid date grammar accepted")
			}
			assertBirthdayInvariant(t, got, err, birthdayTestClock())
		}
	}
	for _, r := range "\u00a0\u200b\u200e\u200f\u061c\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff\u2010\u2212" {
		for _, raw := range []string{string(r) + "2000-01-01", "2000-01-01" + string(r), "2000" + string(r) + "01-01"} {
			got, err := NormalizeBirthday("gregorian", raw, birthdayTestClock())
			if err != ErrInvalidBirthday {
				t.Fatalf("unsupported scalar U+%04X accepted", r)
			}
			assertBirthdayInvariant(t, got, err, birthdayTestClock())
		}
	}
	for r := rune(0); r <= 0x9f; r++ {
		if r > 0x1f && r < 0x7f {
			continue
		}
		got, err := NormalizeBirthday("gregorian", "2000-01-01"+string(r), birthdayTestClock())
		if err != ErrInvalidBirthday {
			t.Fatalf("control U+%04X accepted", r)
		}
		assertBirthdayInvariant(t, got, err, birthdayTestClock())
	}
}

func TestBirthdayCalendarValidity(t *testing.T) {
	now := time.Date(2101, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		calendar, raw string
		valid         bool
	}{
		{"gregorian", "1900-02-28", true}, {"gregorian", "1900-02-29", false},
		{"gregorian", "2000-02-29", true}, {"gregorian", "2000-02-30", false},
		{"gregorian", "2100-02-28", true}, {"gregorian", "2100-02-29", false},
		{"gregorian", "2000-04-30", true}, {"gregorian", "2000-04-31", false},
		{"gregorian", "2000-12-31", true}, {"gregorian", "2000-12-32", false},
		{"gregorian", "2000-00-01", false}, {"gregorian", "2000-13-01", false},
		{"gregorian", "2000-01-00", false}, {"gregorian", "0000-01-01", false},
		{"gregorian", "9999-01-01", false}, {"gregorian", "3799-01-01", false},
		{"jalali", "1395-12-30", true}, {"jalali", "1395-12-31", false},
		{"jalali", "1394-12-29", true}, {"jalali", "1394-12-30", false},
		{"jalali", "1399-12-30", true}, {"jalali", "1400-12-30", false},
		{"jalali", "1403-12-30", true}, {"jalali", "1404-12-30", false},
		{"jalali", "1400-00-01", false}, {"jalali", "1400-13-01", false},
		{"jalali", "1400-01-00", false}, {"jalali", "0000-01-01", false},
		{"jalali", "3178-01-01", false}, {"jalali", "9999-01-01", false},
	} {
		got, err := NormalizeBirthday(tc.calendar, tc.raw, now)
		if (err == nil) != tc.valid {
			t.Fatal("calendar validity mismatch")
		}
		assertBirthdayInvariant(t, got, err, now)
	}
	for month, days := range [...]int{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31} {
		for _, day := range []int{days, days + 1} {
			got, err := NormalizeBirthday("gregorian", formatCivil(civilDate{2000, month + 1, day}), now)
			if (err == nil) != (day == days) {
				t.Fatal("Gregorian month end mismatch")
			}
			assertBirthdayInvariant(t, got, err, now)
		}
	}
	for month := 1; month <= 12; month++ {
		days := 30
		if month <= 6 {
			days = 31
		} else if month == 12 {
			days = 29
		}
		for _, day := range []int{days, days + 1} {
			got, err := NormalizeBirthday("jalali", formatCivil(civilDate{1400, month, day}), now)
			if (err == nil) != (day == days) {
				t.Fatal("Jalali month end mismatch")
			}
			assertBirthdayInvariant(t, got, err, now)
		}
	}
	for _, year := range []int{-1000000000, -62, 3178, 1000000000} {
		if _, _, ok := jalaliCalendar(year); ok {
			t.Fatal("unsupported leap core year accepted")
		}
		if got, ok := jalaliToGregorian(civilDate{year, 1, 1}); ok || got != (civilDate{}) {
			t.Fatal("unsupported converter year accepted")
		}
	}
	for _, year := range []int{-61, 3177} {
		if _, _, ok := jalaliCalendar(year); !ok {
			t.Fatal("documented leap core limit rejected")
		}
	}
	if got, ok := jalaliToGregorian(civilDate{3177, 12, 29}); ok || got != (civilDate{}) {
		t.Fatal("paired converter upper boundary did not fail closed")
	}
}

func TestBirthdayRangeAndTehranClock(t *testing.T) {
	for _, tc := range []struct {
		name      string
		now       time.Time
		candidate civilDate
		valid     bool
	}{
		{"before midnight", time.Date(2026, 11, 14, 20, 29, 59, 999999999, time.UTC), civilDate{2026, 11, 15}, false},
		{"at midnight", time.Date(2026, 11, 14, 20, 30, 0, 0, time.UTC), civilDate{2026, 11, 15}, true},
		{"after midnight", time.Date(2026, 11, 14, 20, 30, 0, 1, time.UTC), civilDate{2026, 11, 15}, true},
		{"before year rollover", time.Date(2026, 12, 31, 20, 29, 59, 0, time.UTC), civilDate{2027, 1, 1}, false},
		{"year rollover", time.Date(2026, 12, 31, 20, 30, 0, 0, time.UTC), civilDate{2027, 1, 1}, true},
		{"after year rollover", time.Date(2026, 12, 31, 20, 30, 1, 0, time.UTC), civilDate{2027, 1, 1}, true},
		{"before DST midnight", time.Date(2021, 7, 1, 19, 29, 59, 0, time.UTC), civilDate{2021, 7, 2}, false},
		{"historical DST midnight", time.Date(2021, 7, 1, 19, 30, 0, 0, time.UTC), civilDate{2021, 7, 2}, true},
		{"before spring DST jump", time.Date(2021, 3, 21, 20, 29, 59, 999999999, time.UTC), civilDate{2021, 3, 22}, false},
		{"spring DST skips local midnight", time.Date(2021, 3, 21, 20, 30, 0, 0, time.UTC), civilDate{2021, 3, 22}, true},
		{"autumn DST repeats prior civil date", time.Date(2021, 9, 21, 19, 30, 0, 0, time.UTC), civilDate{2021, 9, 22}, false},
		{"after repeated hour at midnight", time.Date(2021, 9, 21, 20, 30, 0, 0, time.UTC), civilDate{2021, 9, 22}, true},
		{"current summer no DST", time.Date(2026, 7, 1, 19, 30, 0, 0, time.UTC), civilDate{2026, 7, 2}, false},
		{"current summer midnight", time.Date(2026, 7, 1, 20, 30, 0, 0, time.UTC), civilDate{2026, 7, 2}, true},
		{"today", birthdayTestClock(), civilDate{2026, 11, 15}, true},
		{"tomorrow", birthdayTestClock(), civilDate{2026, 11, 16}, false},
		{"lower bound", birthdayTestClock(), civilDate{1900, 1, 1}, true},
		{"previous day", birthdayTestClock(), civilDate{1899, 12, 31}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jalali, ok := gregorianToJalali(tc.candidate)
			if back, valid := jalaliToGregorian(jalali); !ok || !valid || back != tc.candidate {
				t.Fatal("range fixture conversion is not equivalent")
			}
			for _, location := range []*time.Location{time.UTC, time.FixedZone("other", -7*60*60), time.FixedZone("other east", 13*60*60)} {
				clock := tc.now.In(location)
				for _, calendar := range []string{"gregorian", "jalali"} {
					input := tc.candidate
					if calendar == "jalali" {
						input = jalali
					}
					got, err := NormalizeBirthday(calendar, formatCivil(input), clock)
					if (tc.valid && err != nil) || (!tc.valid && err != ErrInvalidBirthday) {
						t.Fatal("Tehran civil bound mismatch")
					}
					assertBirthdayInvariant(t, got, err, clock)
				}
			}
		})
	}
	for _, now := range []time.Time{{}, time.Date(1, 1, 1, 12, 0, 0, 0, time.UTC), time.Date(1899, 1, 1, 12, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 12, 0, 0, 0, time.UTC), time.Unix(1<<63-1, 0)} {
		got, err := NormalizeBirthday("gregorian", "2000-01-01", now)
		if err != ErrBirthdayClock {
			t.Fatal("unusable clock did not fail operationally")
		}
		assertBirthdayInvariant(t, got, err, now)
	}
}

func TestBirthdayConcurrentConversion(t *testing.T) {
	midnight := time.Date(2025, 3, 20, 20, 30, 0, 0, time.UTC)
	newYear := Birthday{Gregorian: "2025-03-21", Jalali: "1404-01-01"}
	cases := []struct {
		name, calendar, input string
		clock                 time.Time
		pair                  Birthday
		err                   error
	}{
		{"Gregorian at midnight", "gregorian", "2025-03-21", midnight, newYear, nil},
		{"Jalali at midnight", "jalali", "\u06f1\u066404-\u06f01-0\u0661", midnight, newYear, nil},
		{"before midnight", "gregorian", "2025-03-21", midnight.Add(-time.Nanosecond), Birthday{}, ErrInvalidBirthday},
		{"nonleap month end", "jalali", "1404-12-30", birthdayTestClock(), Birthday{}, ErrInvalidBirthday},
		{"zero clock", "jalali", "1404-01-01", time.Time{}, Birthday{}, ErrBirthdayClock},
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			<-start
			for range 32 {
				for _, tc := range cases {
					pair, err := NormalizeBirthday(tc.calendar, tc.input, tc.clock)
					if pair != tc.pair || err != tc.err {
						t.Errorf("concurrent birthday outcome changed for %s", tc.name)
						return
					}
				}
			}
		})
	}
	close(start)
	workers.Wait()
}

func TestBirthdayDailyRoundTrip(t *testing.T) {
	// Deterministic civil increment, independent of converter day ordinals/time.
	last := civilDate{2026, 11, 15}
	count := 0
	for date := (civilDate{1900, 1, 1}); !civilAfter(date, last); {
		got, err := NormalizeBirthday("gregorian", formatCivil(date), birthdayTestClock())
		if err != nil {
			t.Fatal("supported DOB window contains a rejected day")
		}
		assertBirthdayInvariant(t, got, err, birthdayTestClock())
		count++
		date.day++
		if date.day > gregorianMonthDays(date.year, date.month) {
			date.day = 1
			date.month++
			if date.month > 12 {
				date.month = 1
				date.year++
			}
		}
	}
	if count != 46340 {
		t.Fatalf("daily coverage inventory changed: %d", count)
	}
}

func FuzzNormalizeBirthday(f *testing.F) {
	for _, seed := range []struct{ calendar, date string }{
		{"gregorian", "1900-01-01"}, {"gregorian", "1899-12-31"}, {"gregorian", "2000-02-29"},
		{"gregorian", "1900-02-29"}, {"gregorian", "2026-11-15"}, {"gregorian", "2026-11-16"},
		{"jalali", "1395-12-30"}, {"jalali", "1394-12-30"}, {"jalali", "3178-01-01"},
		{"gregorian", "\u06f2\u06f0\u06f0\u06f0-\u06f0\u06f1-\u06f0\u06f1"},
		{"jalali", "\u0661\u06f3\u0669\u06f5-\u0661\u06f2-\u0663\u06f0"},
		{"", ""}, {"persian", "1395-12-30"}, {"gregory", "2000-01-01"},
		{"gregorian", "2000-01-01\u202e"}, {"gregorian", "2000-\xff1-01"},
		{"gregorian", "2000/01/01"}, {"gregorian", "2000-01-01T00:00:00Z"},
		{"gregorian", strings.Repeat("x", 100000)},
	} {
		f.Add(seed.calendar, seed.date, uint8(0))
	}
	f.Add("gregorian", "2000-01-01", uint8(1))
	f.Fuzz(func(t *testing.T, calendar, date string, clockChoice uint8) {
		now := birthdayTestClock()
		if clockChoice%2 == 1 {
			now = time.Time{}
		}
		got, err := NormalizeBirthday(calendar, date, now)
		assertBirthdayInvariant(t, got, err, now)
		if err == nil && (len(date) > 18 || !utf8.ValidString(date) || (calendar != "gregorian" && calendar != "jalali")) {
			t.Fatal("raw admission invariant violated")
		}
	})
}

func assertBirthdayInvariant(t *testing.T, got Birthday, err error, now time.Time) {
	t.Helper()
	if err != nil {
		if got != (Birthday{}) || (err != ErrInvalidBirthday && err != ErrBirthdayClock) {
			t.Fatal("birthday failure returned private data or nonstatic error")
		}
		if ErrInvalidBirthday.Error() != "profile: invalid birthday" || ErrBirthdayClock.Error() != "profile: birthday clock unavailable" {
			t.Fatal("birthday errors are not static and redacted")
		}
		return
	}
	for _, raw := range []string{got.Gregorian, got.Jalali} {
		if len(raw) != 10 {
			t.Fatal("canonical pair is incomplete or not ten ASCII characters")
		}
		for i, r := range raw {
			if i == 4 || i == 7 {
				if r != '-' {
					t.Fatal("canonical date lacks ASCII separators")
				}
			} else if r < '0' || r > '9' {
				t.Fatal("canonical date contains non-ASCII digit")
			}
		}
	}
	gregorian, gOK := parseBirthdayDate(got.Gregorian)
	jalali, jOK := parseBirthdayDate(got.Jalali)
	if back, ok := jalaliToGregorian(jalali); !gOK || !jOK || !ok || back != gregorian {
		t.Fatal("birthday pair is not equivalent")
	}
	for _, calendar := range []string{"gregorian", "jalali"} {
		raw := got.Gregorian
		if calendar == "jalali" {
			raw = got.Jalali
		}
		if again, err := NormalizeBirthday(calendar, raw, now); err != nil || again != got {
			t.Fatal("birthday normalization is not idempotent")
		}
	}
}
