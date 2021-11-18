package httphandler

import (
	"regexp"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func setValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		must(v.RegisterValidation("uuid_zpravy", uuidZpravyValidator))
		must(v.RegisterValidation("dic", dicValidator))
		must(v.RegisterValidation("id_provoz", idProvozValidator))
		must(v.RegisterValidation("id_pokl", idPoklValidator))
		must(v.RegisterValidation("porad_cis", poradCisValidator))
		must(v.RegisterValidation("fin_poloz", finPolozValidator))
		must(v.RegisterValidation("rezim", rezimValidator))
	}
}

func uuidZpravyValidator(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	return match("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fAF]{3}-[0-9a-fA-F]{12}$", s)
}

func dicValidator(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	return match("^CZ[0-9]{8,10}$", s)
}

func idProvozValidator(fl validator.FieldLevel) bool {
	i := fl.Field().Int()
	if i < 1 || i > 999999 {
		return false
	}

	return true
}

func idPoklValidator(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	return match("^[0-9a-zA-Z\\.,:;/#\\-_ ]{1,20}$", s)
}

func poradCisValidator(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	return match("^[0-9a-zA-Z\\.,:;/#\\-_ ]{1,25}$", s)
}

func finPolozValidator(fl validator.FieldLevel) bool {
	f := fl.Field().Float()
	if f >= 0 {
		// positive
		if f > 99999999.99 {
			return false
		}
	} else {
		// negative
		if f > -0.01 || f < -99999999.99 {
			return false
		}
	}

	return true
}

func rezimValidator(fl validator.FieldLevel) bool {
	i := fl.Field().Int()
	if i != 0 && i != 1 {
		return false
	}

	return true
}

func match(pattern, s string) bool {
	ok, err := regexp.MatchString(pattern, s)
	if err != nil {
		panic(err)
	}

	return ok
}
