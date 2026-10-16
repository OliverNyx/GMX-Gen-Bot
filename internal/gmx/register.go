package gmx

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"gmxgen/internal/identity"
)

type RegisterInput struct {
	Person         identity.Person
	Email          string
	CaptchaToken   string
	SkipLogin      bool
	SkipSignupLoad bool
}

type RegisterResult struct {
	Email           string
	Password        string
	Mobile          string
	CCGUID          string
	ConfigCaptcha   string
	AvailabilityOK  bool
	RegisterStatus  int
	RegisterBody    string
	LoginStatus     int
	LoginLocation   string
	HTTPProtocol    string
}

// Register runs the HTTP registration flow from gmx.com.har (without browser automation).
func (c *Client) Register(in RegisterInput) (*RegisterResult, error) {
	if in.CaptchaToken == "" {
		return nil, fmt.Errorf("captcha token required (use CapSkip or pass MAM_... token)")
	}
	res := &RegisterResult{
		Email:    in.Email,
		Password: in.Person.Password,
		Mobile:   in.Person.Mobile,
		CCGUID:   c.CCGUID,
	}

	// Reload signup only when we don't have a valid access token yet.
	// Reloading after Capzy risks invalidating the session that the
	// captcha token is bound to.
	if c.AccessToken == "" {
		if err := c.LoadSignup(); err != nil {
			return res, fmt.Errorf("load signup: %w", err)
		}
	}
	if !in.SkipSignupLoad {
		cfg, err := c.FetchConfiguration()
		if err != nil {
			return res, fmt.Errorf("configuration: %w", err)
		}
		res.ConfigCaptcha = cfg.Captcha
		if cfg.Captcha != "" && cfg.Captcha != "CAPTCHA_FOX" {
			return res, fmt.Errorf("unexpected captcha type %q (HAR expects CAPTCHA_FOX)", cfg.Captcha)
		}
	} else {
		res.ConfigCaptcha = "CAPTCHA_FOX"
	}

	email := in.Email
	avail, err := c.CheckEmailAvailability(email, in.Person.GivenName, in.Person.FamilyName, in.Person.BirthDate)
	if err != nil {
		return res, fmt.Errorf("availability: %w", err)
	}
	if !avail.EmailAddressAvailable {
		if alt := avail.FirstSuggestion(); alt != "" {
			email = alt
			res.Email = email
			avail, err = c.CheckEmailAvailability(email, in.Person.GivenName, in.Person.FamilyName, in.Person.BirthDate)
			if err != nil {
				return res, fmt.Errorf("availability: %w", err)
			}
		}
	}
	// If GMX still rejects, try a few unique locals before giving up.
	for i := 0; !avail.EmailAddressAvailable && i < 4; i++ {
		email = PersonEmail(fmt.Sprintf("%s.%s%d",
			sanitizeLocal(in.Person.GivenName),
			sanitizeLocal(in.Person.FamilyName),
			10000+i*137+len(in.Person.GivenName)*17,
		))
		res.Email = email
		avail, err = c.CheckEmailAvailability(email, in.Person.GivenName, in.Person.FamilyName, in.Person.BirthDate)
		if err != nil {
			return res, fmt.Errorf("availability: %w", err)
		}
		if !avail.EmailAddressAvailable {
			if alt := avail.FirstSuggestion(); alt != "" {
				email = alt
				res.Email = email
				avail, err = c.CheckEmailAvailability(email, in.Person.GivenName, in.Person.FamilyName, in.Person.BirthDate)
				if err != nil {
					return res, fmt.Errorf("availability: %w", err)
				}
			}
		}
	}
	res.AvailabilityOK = avail.EmailAddressAvailable
	if !avail.EmailAddressAvailable {
		return res, fmt.Errorf("email not available: %s", email)
	}

	user := RegistrationUser{
		GivenName:    in.Person.GivenName,
		FamilyName:   in.Person.FamilyName,
		Gender:       in.Person.Gender,
		BirthDate:    in.Person.BirthDate,
		MobileNumber: in.Person.Mobile,
		Address: RegistrationAddress{
			CountryCode:   "US",
			Region:        in.Person.Region,
			PostalCode:    "",
			Locality:      "",
			StreetAddress: "",
		},
		Credentials: RegistrationCreds{Password: in.Person.Password},
	}

	status, body, err := c.RegisterEmail(in.CaptchaToken, user, email)
	if err != nil {
		return res, err
	}
	res.RegisterStatus = status
	res.RegisterBody = string(body)
	res.HTTPProtocol = c.LastProtocol()

	if status != http.StatusNoContent && status != http.StatusOK {
		if status == http.StatusForbidden && strings.Contains(string(body), "Forbidden") {
			return res, fmt.Errorf("registration 403 Forbidden (urn:problem:mam.registration:Forbidden). A fake captcha token on this proxy returns 424, so the request reaches GMX; this 403 is returned only after a live token")
		}
		return res, fmt.Errorf("registration failed: HTTP %d %s", status, truncate(body, 500))
	}

	if !in.SkipLogin {
		loginStatus, loc, err := c.LoginAfterRegistration(email, in.Person.Password)
		if err != nil {
			return res, fmt.Errorf("login: %w", err)
		}
		res.LoginStatus = loginStatus
		res.LoginLocation = loc
	}

	return res, nil
}

func PersonEmail(local string) string {
	return local + "@gmx.com"
}

func sanitizeLocal(s string) string {
	s = strings.ToLower(s)
	var out strings.Builder
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			out.WriteRune(c)
		}
	}
	return out.String()
}
