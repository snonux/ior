package globalfilter

import (
	"reflect"
	"testing"
)

// Clone and Equal list every Filter field by hand. These reflection tests
// make a field added to Filter but forgotten in either list fail here instead
// of silently sharing sub-filters between clones or comparing as equal.

// populatedFilter returns a Filter with every exported field set non-zero,
// discovered via reflection so later-added fields are included.
func populatedFilter(t *testing.T) Filter {
	t.Helper()
	var f Filter
	v := reflect.ValueOf(&f).Elem()
	for i := 0; i < v.NumField(); i++ {
		setNonZero(t, v.Type().Field(i).Name, v.Field(i), 1)
	}
	return f
}

// setNonZero assigns a non-zero value derived from seed to field; different
// seeds yield different values, which the Equal test relies on.
func setNonZero(t *testing.T, name string, field reflect.Value, seed int64) {
	t.Helper()
	switch field.Kind() {
	case reflect.Pointer:
		elem := reflect.New(field.Type().Elem())
		for j := 0; j < elem.Elem().NumField(); j++ {
			setNonZero(t, name, elem.Elem().Field(j), seed)
		}
		field.Set(elem)
	case reflect.String:
		field.SetString(string(rune('a' + seed)))
	case reflect.Int, reflect.Int64:
		field.SetInt(seed)
	case reflect.Bool:
		field.SetBool(seed%2 == 1)
	default:
		t.Fatalf("setNonZero: unhandled kind %s in Filter.%s", field.Kind(), name)
	}
}

// TestFilterCloneCopiesEveryField checks that every pointer field of the
// clone is a distinct allocation holding an equal value, and that scalar
// fields are copied.
func TestFilterCloneCopiesEveryField(t *testing.T) {
	orig := populatedFilter(t)
	clone := orig.Clone()
	ov, cv := reflect.ValueOf(orig), reflect.ValueOf(clone)
	for i := 0; i < ov.NumField(); i++ {
		name := ov.Type().Field(i).Name
		of, cf := ov.Field(i), cv.Field(i)
		if of.Kind() == reflect.Pointer {
			if cf.IsNil() {
				t.Errorf("Clone dropped Filter.%s", name)
				continue
			}
			if of.Pointer() == cf.Pointer() {
				t.Errorf("Clone shares the Filter.%s pointer; add it to Clone", name)
			}
			of, cf = of.Elem(), cf.Elem()
		}
		if !reflect.DeepEqual(of.Interface(), cf.Interface()) {
			t.Errorf("Clone changed Filter.%s: got %v, want %v", name, cf, of)
		}
	}
	if !orig.Equal(clone) {
		t.Fatalf("a filter should Equal its clone")
	}
}

// TestFilterEqualComparesEveryField changes one field at a time (to nil, and
// to a different non-nil value) and requires Equal to notice each change.
func TestFilterEqualComparesEveryField(t *testing.T) {
	base := populatedFilter(t)
	typ := reflect.TypeOf(base)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		t.Run(name, func(t *testing.T) {
			zeroed := base.Clone()
			fv := reflect.ValueOf(&zeroed).Elem().Field(i)
			fv.Set(reflect.Zero(fv.Type()))
			if base.Equal(zeroed) || zeroed.Equal(base) {
				t.Errorf("Equal ignores Filter.%s being cleared; add it to Equal", name)
			}
			if fv.Kind() != reflect.Pointer {
				return
			}
			changed := base.Clone()
			setNonZero(t, name, reflect.ValueOf(&changed).Elem().Field(i), 2)
			if base.Equal(changed) {
				t.Errorf("Equal ignores a different Filter.%s value; add it to Equal", name)
			}
		})
	}
}
