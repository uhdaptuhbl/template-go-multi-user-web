package config

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/sethvargo/go-envconfig"
)

// ErrNilTarget is returned when the decode target is nil, or is a nil pointer.
var ErrNilTarget = errors.New("target cannot be nil")

// ErrNotPointer is returned when the decode target is not a pointer, so there
// is nothing the decoded values could be written into.
var ErrNotPointer = errors.New("target is not a pointer")

// ErrNotStruct is returned when the decode target is a pointer to something
// other than a struct.
var ErrNotStruct = errors.New("target is not a struct pointer")

// CustomValidator defines a custom post-decode validation hook.
//
// Decode calls it after struct-tag validation passes, on the decode target and
// on each of the target's immediate struct fields that implements it. Nesting
// is not followed any further: a struct reached two levels down is never
// called, because the composed configuration is one level deep by design and a
// deeper walk would be a capability nothing here uses.
//
// That gives each package the natural place for a rule its own tags cannot
// express, and leaves the target's own hook for rules that span two of its
// fields. Every hook runs and their failures are joined, so one run reports
// each settings group that is wrong rather than one per restart. A hook is
// therefore not entitled to assume that any other hook succeeded: one that
// reads state another derives checks what it reads rather than trusting it.
// Struct-tag validation is the one stage that does gate, so no hook sees
// values the tags reject.
//
// The hook is looked up on the addressable field, so implementing it on a
// pointer receiver is correct and lets it write back to what it validated.
type CustomValidator interface {
	Validate(ctx context.Context) error
}

// Decode reads values from lookuper into target and validates the result.
//
// Passing nil for lookuper reads the real process environment. Tests should
// pass envconfig.MapLookuper instead, so they neither mutate process state nor
// have to run serially.
//
// Values are decoded into target, then validated against its
// go-playground/validator struct tags, then passed to the CustomValidator of
// each immediate struct field that implements one and to the target's own.
// Decoding and tag validation each gate what comes after them, so no custom
// validator sees values the tags reject. The hooks do not gate each other:
// all of them run, and their failures are reported together.
//
// The target must be a non-nil pointer to a struct; otherwise Decode returns
// ErrNilTarget, ErrNotPointer, or ErrNotStruct.
func Decode(ctx context.Context, target any, lookuper envconfig.Lookuper, mutators ...envconfig.Mutator) error {
	if target == nil {
		return ErrNilTarget
	}
	if val := reflect.ValueOf(target); val.Kind() != reflect.Pointer {
		return ErrNotPointer
	} else if val.IsNil() {
		return ErrNilTarget
	} else if val.Elem().Kind() != reflect.Struct {
		return ErrNotStruct
	}

	// A nil Lookuper is passed through rather than replaced: go-envconfig
	// already falls back to envconfig.OsLookuper for one, so substituting it
	// here would be a branch no test could ever distinguish.
	cfgProcess := envconfig.Config{
		Target:   target,
		Lookuper: lookuper,
		Mutators: mutators,
	}

	if err := envconfig.ProcessWith(ctx, &cfgProcess); err != nil {
		return fmt.Errorf("reading environment values: %w", err)
	}

	// WithRequiredStructEnabled opts in to the behaviour validator v11 will
	// make the default, so the rules mean the same thing before and after that
	// release rather than changing under a dependency bump.
	validate := validator.New(validator.WithRequiredStructEnabled())

	// The failure is wrapped without being classified first. validator returns
	// either an InvalidValidationError, which the target checks above have
	// already ruled out, or a ValidationErrors that callers reach with
	// errors.As through this wrapping. Sorting them here produced two branches
	// that returned the same text and one that could not be reached.
	if err := validate.Struct(target); err != nil {
		return fmt.Errorf("validating configuration: %w", err)
	}

	fieldErr := validateFields(ctx, target)

	var targetErr error

	if custom, ok := target.(CustomValidator); ok {
		if err := custom.Validate(ctx); err != nil {
			targetErr = fmt.Errorf("running custom validation: %w", err)
		}
	}

	// Joined rather than returned one at a time: the two layers check different
	// things, and an operator writing a configuration from scratch should learn
	// about both from one run. Join drops nils, so a clean decode returns nil.
	return errors.Join(fieldErr, targetErr)
}

// validateFields runs the CustomValidator hook on each immediate struct field
// of target that implements one, and joins their failures rather than stopping
// at the first, so one run tells an operator about every settings group that is
// wrong instead of one per restart.
//
// Each failure is labelled with the variable prefix the field's env tag
// declares. A package's own validator knows what is wrong with its values but
// not what an operator calls them: two instances of one config type are told
// apart only by the prefix the composing struct gives them, so the label has to
// come from here.
func validateFields(ctx context.Context, target any) error {
	value := reflect.ValueOf(target).Elem()
	structType := value.Type()

	errs := make([]error, 0, structType.NumField())

	for index := range structType.NumField() {
		field := structType.Field(index)
		if !field.IsExported() || field.Type.Kind() != reflect.Struct {
			continue
		}

		custom, ok := reflect.TypeAssert[CustomValidator](value.Field(index).Addr())
		if !ok {
			continue
		}

		if err := custom.Validate(ctx); err != nil {
			errs = append(errs, fmt.Errorf("validating %s: %w", envLabel(field), err))
		}
	}

	return errors.Join(errs...)
}

// envLabel names a field the way an operator sees it: the variable prefix its
// env tag declares, or its Go field name when the tag declares none, as is the
// case for settings whose variable names are fixed outside this project.
func envLabel(field reflect.StructField) string {
	if prefix := envTagPrefix(field); prefix != "" {
		return prefix
	}

	return field.Name
}

// envTagPrefix returns the variable-name prefix a field's env tag applies to
// the settings nested inside it, or an empty string when it declares none.
//
// go-envconfig's tag is a comma-separated list whose first element is a
// variable name and whose remaining elements are options; prefix= is the option
// that namespaces a nested struct.
func envTagPrefix(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("env")
	if !ok {
		return ""
	}

	options := strings.Split(tag, ",")

	for _, option := range options[1:] {
		if prefix, found := strings.CutPrefix(strings.TrimSpace(option), "prefix="); found {
			return prefix
		}
	}

	return ""
}

// envTagName returns the variable name a field's env tag declares, without any
// prefix a composing struct may add to it, or an empty string when the tag
// declares no name.
func envTagName(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("env")
	if !ok {
		return ""
	}

	name, _, _ := strings.Cut(tag, ",")

	return strings.TrimSpace(name)
}
