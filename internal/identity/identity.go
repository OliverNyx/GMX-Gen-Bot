package identity

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
	"unicode"

	"gmxgen/internal/phone"
)

type Person struct {
	GivenName  string
	FamilyName string
	Gender     string
	BirthDate  string // YYYY-MM-DD
	Mobile     string
	Region     string // US state code
	EmailLocal string
	Password   string
}

var firstNames = []string{
	"james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
	"william", "elizabeth", "david", "barbara", "richard", "susan", "joseph", "jessica",
	"thomas", "sarah", "charles", "karen", "christopher", "lisa", "daniel", "nancy",
	"matthew", "betty", "anthony", "margaret", "mark", "sandra", "donald", "ashley",
	"steven", "kimberly", "paul", "emily", "andrew", "donna", "joshua", "michelle",
}

var lastNames = []string{
	"smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis",
	"rodriguez", "martinez", "hernandez", "lopez", "gonzalez", "wilson", "anderson",
	"thomas", "taylor", "moore", "jackson", "martin", "lee", "perez", "thompson",
	"white", "harris", "sanchez", "clark", "ramirez", "lewis", "robinson", "walker",
}

var usRegions = []string{
	"AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID", "IL", "IN",
	"IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV",
	"NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN",
	"TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
}

func pick(r *rand.Rand, list []string) string {
	return list[r.Intn(len(list))]
}

func randomPassword(r *rand.Rand) string {
	lower := "abcdefghjkmnpqrstuvwxyz"
	upper := "ABCDEFGHJKMNPQRSTUVWXYZ"
	digits := "23456789"
	special := "#$%&*"
	var b strings.Builder
	for i := 0; i < 4; i++ {
		b.WriteByte(lower[r.Intn(len(lower))])
	}
	for i := 0; i < 3; i++ {
		b.WriteByte(upper[r.Intn(len(upper))])
	}
	for i := 0; i < 3; i++ {
		b.WriteByte(digits[r.Intn(len(digits))])
	}
	b.WriteByte(special[r.Intn(len(special))])
	return b.String()
}

func emailLocal(given, family string, r *rand.Rand) string {
	g := sanitize(given)
	f := sanitize(family)
	n := 1000 + r.Intn(9000)
	patterns := []string{
		fmt.Sprintf("%s.%s%d", g, f, n),
		fmt.Sprintf("%s%s%d", g, f, n),
		fmt.Sprintf("%s_%s%d", g, f, n),
		fmt.Sprintf("%s.%s.%d", g, f, n),
	}
	return patterns[r.Intn(len(patterns))]
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var out strings.Builder
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			out.WriteRune(c)
		}
	}
	return out.String()
}

// Random builds registration identity aligned with HAR payloads.
func Random(r *rand.Rand) Person {
	given := pick(r, firstNames)
	family := pick(r, lastNames)
	gender := "MALE"
	if r.Intn(2) == 0 {
		gender = "FEMALE"
	}
	year := 1975 + r.Intn(28)
	month := 1 + r.Intn(12)
	day := 1 + r.Intn(28)
	birth := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
	return Person{
		GivenName:  title(given),
		FamilyName: title(family),
		Gender:     gender,
		BirthDate:  birth,
		Mobile:     phone.E164(r),
		Region:     pick(r, usRegions),
		EmailLocal: emailLocal(given, family, r),
		Password:   randomPassword(r),
	}
}
