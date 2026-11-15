package profile

import "errors"

// Gender has no valid zero value or inferred default for new data.
type Gender string

// Explicit supported gender values.
const (
	GenderFemale Gender = "female"
	GenderMale   Gender = "male"
)

// ErrInvalidGender never includes the rejected private value.
var ErrInvalidGender = errors.New("profile: invalid gender")

// ValidateGender admits exact wire values only, without normalization or defaults.
func ValidateGender(raw string) (Gender, error) {
	switch raw {
	case string(GenderFemale):
		return GenderFemale, nil
	case string(GenderMale):
		return GenderMale, nil
	default:
		return "", ErrInvalidGender
	}
}
