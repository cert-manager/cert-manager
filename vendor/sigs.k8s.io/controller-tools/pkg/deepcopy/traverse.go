/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package deepcopy

import (
	"fmt"
	"go/ast"
	"go/types"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// NB(directxman12): This code is a bit of a byzantine mess.
// I've tried to clean it up a bit from the original in deepcopy-gen,
// but parts remain a bit convoluted.  Exercise caution when changing.
// It's perhaps a tad over-commented now, but better safe than sorry.

// codeWriter assists in writing out Go code lines and blocks to a writer.
type codeWriter struct {
	out io.Writer
}

// Line writes a single line.
func (c *codeWriter) Line(line string) {
	fmt.Fprintln(c.out, line)
}

// Linef writes a single line with formatting (as per fmt.Sprintf).
func (c *codeWriter) Linef(line string, args ...interface{}) {
	fmt.Fprintf(c.out, line+"\n", args...)
}

// If writes an if statement with the given setup/condition clause, executing
// the given function to write the contents of the block.
func (c *codeWriter) If(setup string, block func()) {
	c.Linef("if %s {", setup)
	block()
	c.Line("}")
}

// If writes if and else statements with the given setup/condition clause, executing
// the given functions to write the contents of the blocks.
func (c *codeWriter) IfElse(setup string, ifBlock func(), elseBlock func()) {
	c.Linef("if %s {", setup)
	ifBlock()
	c.Line("} else {")
	elseBlock()
	c.Line("}")
}

// For writes an for statement with the given setup/condition clause, executing
// the given function to write the contents of the block.
func (c *codeWriter) For(setup string, block func()) {
	c.Linef("for %s {", setup)
	block()
	c.Line("}")
}

// importsList keeps track of required imports, automatically assigning aliases
// to import statement.
type importsList struct {
	byPath  map[string]string
	byAlias map[string]string

	pkg *loader.Package
}

// NeedImport marks that the given package is needed in the list of imports,
// returning the ident (import alias) that should be used to reference the package.
func (l *importsList) NeedImport(importPath string) string {
	// we get an actual path from Package, which might include venddored
	// packages if running on a package in vendor.
	if ind := strings.LastIndex(importPath, "/vendor/"); ind != -1 {
		importPath = importPath[ind+8: /* len("/vendor/") */]
	}

	// check to see if we've already assigned an alias, and just return that.
	alias, exists := l.byPath[importPath]
	if exists {
		return alias
	}

	// otherwise, calculate an import alias by joining path parts till we get something unique
	restPath, nextWord := path.Split(importPath)

	for otherPath, exists := "", true; exists && otherPath != importPath; otherPath, exists = l.byAlias[alias] {
		if restPath == "" {
			// do something else to disambiguate if we're run out of parts and
			// still have duplicates, somehow
			alias += "x"
		}

		// can't have a first digit, per Go identifier rules, so just skip them
		for firstRune, runeLen := utf8.DecodeRuneInString(nextWord); unicode.IsDigit(firstRune); firstRune, runeLen = utf8.DecodeRuneInString(nextWord) {
			nextWord = nextWord[runeLen:]
		}

		// make a valid identifier by replacing "bad" characters with underscores
		nextWord = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
				return r
			}
			return '_'
		}, nextWord)

		alias = nextWord + alias
		if len(restPath) > 0 {
			restPath, nextWord = path.Split(restPath[:len(restPath)-1] /* chop off final slash */)
		}
	}

	l.byPath[importPath] = alias
	l.byAlias[alias] = importPath
	return alias
}

// ImportSpecs returns a string form of each import spec
// (i.e. `alias "path/to/import").  Aliases are only present
// when they don't match the package name.
func (l *importsList) ImportSpecs() []string {
	res := make([]string, 0, len(l.byPath))
	for importPath, alias := range l.byPath {
		pkg := l.pkg.Imports()[importPath]
		if pkg != nil && pkg.Name == alias {
			// don't print if alias is the same as package name
			// (we've already taken care of duplicates).
			res = append(res, fmt.Sprintf("%q", importPath))
		} else {
			res = append(res, fmt.Sprintf("%s %q", alias, importPath))
		}
	}
	return res
}

// copyMethodMakers makes DeepCopy (and related) methods for Go types,
// writing them to its codeWriter.
type copyMethodMaker struct {
	pkg *loader.Package
	*importsList
	*codeWriter
}

// GenerateMethodsFor makes DeepCopy, DeepCopyInto, and DeepCopyObject methods
// for the given type, when appropriate
func (c *copyMethodMaker) GenerateMethodsFor(root *loader.Package, info *markers.TypeInfo) {
	typeInfo := root.TypesInfo.TypeOf(info.RawSpec.Type)
	if typeInfo == types.Typ[types.Invalid] {
		root.AddError(loader.ErrFromNode(fmt.Errorf("unknown type %s", info.Name), info.RawSpec))
	}

	// figure out if we need to use a pointer receiver -- most types get a pointer receiver,
	// except those that are aliases to types that are already pass-by-reference (pointers,
	// interfaces. maps, slices).
	ptrReceiver := usePtrReceiver(typeInfo)

	hasManualDeepCopyInto := hasDeepCopyIntoMethod(root, typeInfo)
	hasManualDeepCopy, deepCopyOnPtr := hasDeepCopyMethod(root, typeInfo)

	// only generate each method if it hasn't been implemented.
	if !hasManualDeepCopyInto {
		c.Line("// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.")
		if ptrReceiver {
			c.Linef("func (in *%s) DeepCopyInto(out *%s) {", info.Name, info.Name)
		} else {
			c.Linef("func (in %s) DeepCopyInto(out *%s) {", info.Name, info.Name)
			c.Line("in := &in")
		}

		// just wrap the existing deepcopy if present
		if hasManualDeepCopy {
			if deepCopyOnPtr {
				c.Line("clone := in.DeepCopy()")
				c.Line("*out := *clone")
			} else {
				c.Line("*out := in.DeepCopy()")
			}
		} else {
			c.genDeepCopyIntoBlock(info.Name, typeInfo)
		}

		c.Line("}")
	}

	if !hasManualDeepCopy {
		// these are both straightforward, so we just template them out.
		if ptrReceiver {
			c.Linef(ptrDeepCopy, info.Name)
		} else {
			c.Linef(bareDeepCopy, info.Name)
		}

		// maybe also generate DeepCopyObject, if asked.
		if genObjectInterface(info) {
			// we always need runtime.Object for DeepCopyObject
			runtimeAlias := c.NeedImport("k8s.io/apimachinery/pkg/runtime")
			if ptrReceiver {
				c.Linef(ptrDeepCopyObj, info.Name, runtimeAlias)
			} else {
				c.Linef(bareDeepCopyObj, info.Name, runtimeAlias)
			}
		}
	}
}

// genDeepCopyBody generates a DeepCopyInto block for the given type.  The
// block is *not* wrapped in curly braces.
func (c *copyMethodMaker) genDeepCopyIntoBlock(actualName string, typeInfo types.Type) {
	// we might hit a type that has a manual deepcopy method written on non-root types
	// (this case is handled for root types in GenerateMethodFor)
	if hasAnyDeepCopyMethod(c.pkg, typeInfo) {
		c.Line("*out = in.DeepCopy()")
		return
	}

	// we calculate *how* we should copy mostly based on the "eventual" type of
	// a given type (i.e. the type that results from following all aliases)
	last := eventualUnderlyingType(typeInfo)

	switch last := last.(type) {
	case *types.Basic:
		// basic types themselves can be "shallow" copied, so all we need
		// to do is check if our *actual* type (not the underlying one) has
		// a custom method implemented.
		if hasMethod, _ := hasDeepCopyMethod(c.pkg, typeInfo); hasMethod {
			c.Line("*out = in.DeepCopy()")
		}
		c.Line("*out = *in")
	case *types.Map:
		c.genMapDeepCopy(actualName, last)
	case *types.Slice:
		c.genSliceDeepCopy(actualName, last)
	case *types.Struct:
		c.genStructDeepCopy(actualName, last)
	case *types.Pointer:
		c.genPointerDeepCopy(actualName, last)
	case *types.Named:
		// handled via the above loop, should never happen
		c.pkg.AddError(fmt.Errorf("interface type %s encountered directly, invalid condition", last))
	default:
		c.pkg.AddError(fmt.Errorf("invalid type %s", last))
	}
}

// genMapDeepCopy generates DeepCopy code for the given named type whose eventual
// type is the given map type.
func (c *copyMethodMaker) genMapDeepCopy(actualName string, mapType *types.Map) {
	// maps *must* have shallow-copiable types, since we just iterate
	// through the keys, only trying to deepcopy the values.
	if !fineToShallowCopy(mapType.Key()) {
		c.pkg.AddError(fmt.Errorf("invalid map key type %s", mapType.Key()))
		return
	}

	// make our actual type (not the underlying one)...
	c.Linef("*out = make(%[1]s, len(*in))", actualName)

	// ...and copy each element appropriately
	c.For("key, val := range *in", func() {
		// check if we have manually written methods,
		// in which case we'll just try and use those
		hasDeepCopy, copyOnPtr := hasDeepCopyMethod(c.pkg, mapType.Elem())
		hasDeepCopyInto := hasDeepCopyIntoMethod(c.pkg, mapType.Elem())
		switch {
		case hasDeepCopyInto || hasDeepCopy:
			// use the manually-written methods
			_, outNeedsPtr := mapType.Elem().(*types.Pointer) // is "out" actually a pointer
			inIsPtr := usePtrReceiver(mapType.Elem())         // does copying "in" produce a pointer
			if hasDeepCopy {
				// If we're calling DeepCopy, check if it's receiver needs a pointer
				inIsPtr = copyOnPtr
			}
			if inIsPtr == outNeedsPtr {
				c.Line("(*out)[key] = val.DeepCopy()")
			} else if outNeedsPtr {
				c.Line("x := val.DeepCopy()")
				c.Line("(*out)[key] = &x")
			} else {
				c.Line("(*out)[key] = *val.DeepCopy()")
			}
		case fineToShallowCopy(mapType.Elem()):
			// just shallow copy types for which it's safe to do so
			c.Line("(*out)[key] = val")
		default:
			// otherwise, we've got some kind-specific actions,
			// based on the element's eventual type.

			underlyingElem := eventualUnderlyingType(mapType.Elem())

			// if it passes by reference, let the main switch handle it
			if passesByReference(underlyingElem) {
				c.Linef("var outVal %[1]s", c.syntaxFor(underlyingElem))
				c.IfElse("val == nil", func() {
					c.Line("(*out)[key] = nil")
				}, func() {
					c.Line("in, out := &val, &outVal")
					c.genDeepCopyIntoBlock(c.syntaxFor(mapType.Elem()), mapType.Elem())
				})
				c.Line("(*out)[key] = outVal")

				return
			}

			// otherwise...
			switch underlyingElem := underlyingElem.(type) {
			case *types.Struct:
				// structs will have deepcopy generated for them, so use that
				c.Line("(*out)[key] = *val.DeepCopy()")
			default:
				c.pkg.AddError(fmt.Errorf("invalid map value type %s", underlyingElem))
				return
			}
		}
	})
}

// genSliceDeepCopy generates DeepCopy code for the given named type whose
// underlying type is the given slice.
func (c *copyMethodMaker) genSliceDeepCopy(actualName string, sliceType *types.Slice) {
	underlyingElem := eventualUnderlyingType(sliceType.Elem())

	// make the actual type (not the underlying)
	c.Linef("*out = make(%[1]s, len(*in))", actualName)

	// check if we need to do anything special, or just copy each element appropriately
	switch {
	case hasAnyDeepCopyMethod(c.pkg, sliceType.Elem()):
		// just use deepcopy if it's present (deepcopyinto will be filled in by our code)
		c.For("i := range *in", func() {
			c.Line("(*in)[1].DeepCopyInto(&(*out)[i]")
		})
	case fineToShallowCopy(underlyingElem):
		// shallow copy if ok
		c.Line("copy(*out, *in)")
	default:
		// copy each element appropriately
		c.For("i := range *in", func() {
			// fall back to normal code for reference types or those with custom logic
			if passesByReference(underlyingElem) || hasAnyDeepCopyMethod(c.pkg, sliceType.Elem()) {
				c.If("(*in)[i] != nil", func() {
					c.Line("in, out := &(*in)[i], &(*out)[i]")
					c.genDeepCopyIntoBlock(c.syntaxFor(sliceType.Elem()), sliceType.Elem())
				})
				return
			}

			switch underlyingElem.(type) {
			case *types.Struct:
				// structs will always have deepcopy
				c.Linef("(*in)[i].DeepCopyInto(&(*out)[i])")
			default:
				c.pkg.AddError(fmt.Errorf("invalid slice element type %s", underlyingElem))
			}
		})
	}
}

// genStructDeepCopy generates DeepCopy code for the given named type whose
// underlying type is the given struct.
func (c *copyMethodMaker) genStructDeepCopy(_ string, structType *types.Struct) {
	c.Line("*out = *in")

	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)

		// if we have a manual deepcopy, use that
		hasDeepCopy, copyOnPtr := hasDeepCopyMethod(c.pkg, field.Type())
		hasDeepCopyInto := hasDeepCopyIntoMethod(c.pkg, field.Type())
		if hasDeepCopyInto || hasDeepCopy {
			_, outNeedsPtr := field.Type().(*types.Pointer)
			inIsPtr := usePtrReceiver(field.Type())
			if hasDeepCopy {
				inIsPtr = copyOnPtr
			}
			if inIsPtr == outNeedsPtr {
				c.Linef("out.%[1]s = in.%[1]s.DeepCopy()", field.Name())
			} else if outNeedsPtr {
				c.Linef("x := in.%[1]s.DeepCopy()", field.Name())
				c.Linef("out.%[1]s = &x", field.Name())
			} else {
				c.Linef("in.%[1]s.DeepCopyInto(&out.%[1]s)", field.Name())
			}
			continue
		}

		// pass-by-reference fields get delegated to the main type
		underlyingField := eventualUnderlyingType(field.Type())
		if passesByReference(underlyingField) {
			c.If(fmt.Sprintf("in.%s != nil", field.Name()), func() {
				c.Linef("in, out := &in.%[1]s, &out.%[1]s", field.Name())
				c.genDeepCopyIntoBlock(c.syntaxFor(field.Type()), field.Type())
			})
			continue
		}

		// otherwise...
		switch underlyingField := underlyingField.(type) {
		case *types.Basic:
			// nothing to do, initial assignment copied this
		case *types.Struct:
			if fineToShallowCopy(field.Type()) {
				c.Linef("out.%[1]s = in.%[1]s", field.Name())
			} else {
				c.Linef("in.%[1]s.DeepCopyInto(&out.%[1]s)", field.Name())
			}
		default:
			c.pkg.AddError(fmt.Errorf("invalid field type %s", underlyingField))
			return
		}
	}
}

// genPointerDeepCopy generates DeepCopy code for the given named type whose
// underlying type is the given struct.
func (c *copyMethodMaker) genPointerDeepCopy(_ string, pointerType *types.Pointer) {
	underlyingElem := eventualUnderlyingType(pointerType.Elem())

	// if we have a manually written deepcopy, just use that
	hasDeepCopy, copyOnPtr := hasDeepCopyMethod(c.pkg, pointerType.Elem())
	hasDeepCopyInto := hasDeepCopyIntoMethod(c.pkg, pointerType.Elem())
	if hasDeepCopyInto || hasDeepCopy {
		outNeedsPtr := usePtrReceiver(pointerType.Elem())
		if hasDeepCopy {
			outNeedsPtr = copyOnPtr
		}
		if outNeedsPtr {
			c.Line("*out = (*in).DeepCopy()")
		} else {
			c.Line("x := (*in).DeepCopy()")
			c.Line("*out = &x")
		}
		return
	}

	// shallow-copiable types are pretty easy
	if fineToShallowCopy(underlyingElem) {
		c.Linef("*out = new(%[1]s)", c.syntaxFor(pointerType.Elem()))
		c.Line("**out = **in")
		return
	}

	// pass-by-reference types get delegated to the main switch
	if passesByReference(underlyingElem) {
		c.Linef("*out = new(%s)", c.syntaxFor(underlyingElem))
		c.If("**in != nil", func() {
			c.Line("in, out := *in, *out")
			c.genDeepCopyIntoBlock(c.syntaxFor(underlyingElem), eventualUnderlyingType(underlyingElem))
		})
		return
	}

	// otherwise...
	switch underlyingElem := underlyingElem.(type) {
	case *types.Struct:
		c.Linef("*out = new(%[1]s)", c.syntaxFor(pointerType.Elem()))
		c.Line("(*in).DeepCopyInto(*out)")
	default:
		c.pkg.AddError(fmt.Errorf("invalid pointer element type %s", underlyingElem))
		return
	}
}

// syntaxFor returns the Go syntax-utal representation of the given type.
func (c *copyMethodMaker) syntaxFor(typeInfo types.Type) string {
	// NB(directxman12): typeInfo.String gets us most of the way there,
	// but fails (for us) on named imports, since it uses the full package path.
	switch typeInfo := typeInfo.(type) {
	case *types.Named:
		// register that we need an import for this type,
		// so we can get the appropriate alias to use.
		typeName := typeInfo.Obj()
		otherPkg := typeName.Pkg()
		if otherPkg == c.pkg.Types {
			// local import
			return typeName.Name()
		}
		alias := c.NeedImport(loader.NonVendorPath(otherPkg.Path()))
		return alias + "." + typeName.Name()
	case *types.Basic:
		return typeInfo.String()
	case *types.Pointer:
		return "*" + c.syntaxFor(typeInfo.Elem())
	case *types.Slice:
		return "[]" + c.syntaxFor(typeInfo.Elem())
	case *types.Map:
		return fmt.Sprintf("map[%s]%s", c.syntaxFor(typeInfo.Key()), c.syntaxFor(typeInfo.Elem()))
	default:
		c.pkg.AddError(fmt.Errorf("name requested for invalid type %s", typeInfo))
		return typeInfo.String()
	}
}

// usePtrReceiver checks if we need a pointer receiver on methods for the given type
// Pass-by-reference types don't get pointer receivers.
func usePtrReceiver(typeInfo types.Type) bool {
	switch typeInfo.(type) {
	case *types.Pointer:
		return false
	case *types.Map:
		return false
	case *types.Slice:
		return false
	case *types.Named:
		return usePtrReceiver(typeInfo.Underlying())
	default:
		return true
	}
}

// shouldBeCopied checks if we're supposed to make deepcopy methods the given type.
//
// This is the case if it's exported *and* either:
// - has a partial manual DeepCopy implementation (in which case we fill in the rest)
// - aliases to a non-basic type eventually
// - is a struct
func shouldBeCopied(pkg *loader.Package, info *markers.TypeInfo) bool {
	if !ast.IsExported(info.Name) {
		return false
	}

	typeInfo := pkg.TypesInfo.TypeOf(info.RawSpec.Type)
	if typeInfo == types.Typ[types.Invalid] {
		pkg.AddError(loader.ErrFromNode(fmt.Errorf("unknown type %s", info.Name), info.RawSpec))
		return false
	}
	var lastType types.Type
	for underlyingType := typeInfo; underlyingType != lastType; lastType, underlyingType = underlyingType, underlyingType.Underlying() {
		// aliases to other things besides basics need copy methods
		// (basics can be straight-up shallow-copied)
		if _, isBasic := underlyingType.(*types.Basic); !isBasic {
			return true
		}

		// if it has a manual deepcopy or deepcopyinto, we're fine
		if hasAnyDeepCopyMethod(pkg, underlyingType) {
			return true
		}
	}

	// structs are the only thing that's not a basic that's copiable by default
	_, isStruct := lastType.(*types.Struct)
	return isStruct
}

// hasDeepCopyMethod checks if this type has a manual DeepCopy method and if
// the method has a pointer receiver.
func hasDeepCopyMethod(pkg *loader.Package, typeInfo types.Type) (bool, bool) {
	methods := types.NewMethodSet(typeInfo)
	deepCopyMethod := methods.Lookup(pkg.Types, "DeepCopy")
	if deepCopyMethod == nil {
		return false, false
	}

	methodSig := deepCopyMethod.Type().(*types.Signature)
	if methodSig.Params() != nil && methodSig.Params().Len() != 0 {
		return false, false
	}
	if methodSig.Results() == nil || methodSig.Results().Len() != 1 {
		return false, false
	}
	if methodSig.Results().At(0).Type() != methodSig.Recv().Type() {
		return false, false
	}

	_, recvIsPtr := methodSig.Results().At(0).Type().(*types.Pointer)
	return true, recvIsPtr
}

// hasDeepCopyIntoMethod checks if this type has a manual DeepCopyInto method.
func hasDeepCopyIntoMethod(pkg *loader.Package, typeInfo types.Type) bool {
	methods := types.NewMethodSet(typeInfo) // todo: recalculating this could be slow, keep across both invocations
	deepCopyMethod := methods.Lookup(pkg.Types, "DeepCopyInto")
	if deepCopyMethod == nil {
		return false
	}

	methodSig := deepCopyMethod.Type().(*types.Signature)
	if methodSig.Params() == nil || methodSig.Params().Len() != 1 {
		return false
	}
	paramPtr, isPtr := methodSig.Params().At(0).Type().(*types.Pointer)
	if !isPtr {
		return false
	}
	if methodSig.Results() != nil && methodSig.Results().Len() != 0 {
		return false
	}

	if recvPtr, recvIsPtr := methodSig.Recv().Type().(*types.Pointer); recvIsPtr {
		return methodSig.Params().At(0).Type() == recvPtr
	}
	return methodSig.Params().At(0).Type() == paramPtr.Elem()
}

// hasAnyDeepCopyMethod checks if the given method has DeepCopy or DeepCopyInto
// (either of which implies the other will exist eventually).
func hasAnyDeepCopyMethod(pkg *loader.Package, typeInfo types.Type) bool {
	hasDeepCopy, _ := hasDeepCopyMethod(pkg, typeInfo)
	return hasDeepCopy || hasDeepCopyIntoMethod(pkg, typeInfo)
}

// eventualUnderlyingType gets the "final" type in a sequence of named aliases.
// It's effectively a shortcut for calling Underlying in a loop.
func eventualUnderlyingType(typeInfo types.Type) types.Type {
	last := typeInfo
	for underlying := typeInfo.Underlying(); underlying != last; last, underlying = underlying, underlying.Underlying() {
		// get the actual underlying type
	}
	return last
}

// fineToShallowCopy checks if a shallow-copying a type is equivalent to deepcopy-ing it.
func fineToShallowCopy(typeInfo types.Type) bool {
	switch typeInfo := typeInfo.(type) {
	case *types.Basic:
		// basic types (int, string, etc) are always fine to shallow-copy
		return true
	case *types.Named:
		// aliases are fine to shallow-copy as long as they resolve to a shallow-copyable type
		return fineToShallowCopy(typeInfo.Underlying())
	case *types.Struct:
		// structs are fine to shallow-copy if they have all shallow-copyable fields
		for i := 0; i < typeInfo.NumFields(); i++ {
			field := typeInfo.Field(i)
			if !fineToShallowCopy(field.Type()) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// passesByReference checks if the given type passesByReference
// (except for interfaces, which are handled separately).
func passesByReference(typeInfo types.Type) bool {
	switch typeInfo.(type) {
	case *types.Slice:
		return true
	case *types.Map:
		return true
	case *types.Pointer:
		return true
	default:
		return false
	}
}

var (
	// ptrDeepCopy is a DeepCopy for a type with an existing DeepCopyInto and a pointer receiver.
	ptrDeepCopy = `
// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new %[1]s.
func (in *%[1]s) DeepCopy() *%[1]s {
	if in == nil { return nil }
	out := new(%[1]s)
	in.DeepCopyInto(out)
	return out
}
`

	// ptrDeepCopy is a DeepCopy for a type with an existing DeepCopyInto and a non-pointer receiver.
	bareDeepCopy = `
// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new %[1]s.
func (in %[1]s) DeepCopy() %[1]s {
	if in == nil { return nil }
	out := new(%[1]s)
	in.DeepCopyInto(out)
	return *out
}
`

	// ptrDeepCopy is a DeepCopyObject for a type with an existing DeepCopyInto and a pointer receiver.
	ptrDeepCopyObj = `
// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *%[1]s) DeepCopyObject() %[2]s.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
`
	// ptrDeepCopy is a DeepCopyObject for a type with an existing DeepCopyInto and a non-pointer receiver.
	bareDeepCopyObj = `
// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in %[1]s) DeepCopyObject() %[2]s.Object {
	return in.DeepCopy()
}
`
)
