// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checklocks

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"sync/atomic"

	"golang.org/x/tools/go/ssa"
)

// lockType represents the current state of the lock.
// The 0 value represents the unlocked state.
type lockType int

const (
	unlocked lockType = iota
	locked
	deferredunlock
	lockedAndDeferredUnlock
)

// isLocked checks if `l` is in a locked state.
func (l lockType) isLocked() bool {
	return l == locked || l == lockedAndDeferredUnlock
}

// isUnlocked checks if `l` is in an unlocked state.
func (l lockType) isUnlocked() bool {
	return l == unlocked || l == deferredunlock
}

// hasDeferredUnlock checks if `l` has a deferred unlock.
func (l lockType) hasDeferredUnlock() bool {
	return l == deferredunlock || l == lockedAndDeferredUnlock
}

// lock transitions the lock type to a locked state.
// If the lock type is already locked, return the same state
func (l lockType) lock() lockType {
	switch l {
	case unlocked:
		return locked
	case deferredunlock:
		return lockedAndDeferredUnlock
	default:
		return l
	}
}

// lock transitions the lock type to an unlocked state.
// If the lock type is already unlocked, return the same state
func (l lockType) unlock() lockType {
	switch l {
	case locked:
		return unlocked
	case lockedAndDeferredUnlock:
		return deferredunlock
	default:
		return l
	}
}

// lock transitions the lock type to a same state with a deferred unlock.
// If the lock type already has a deferred unlock, return the same state
func (l lockType) deferUnlock() lockType {
	switch l {
	case unlocked:
		return deferredunlock
	case locked:
		return lockedAndDeferredUnlock
	default:
		return l
	}
}

// lockState tracks the locking state and aliases.
type lockState struct {
	// mutexes is used to track which mutexes in a given struct are
	// currently locked. Note that most of the heavy lifting is done by
	// valueAsString below, which maps to specific structure fields, etc.
	mutexes map[string]lockType

	// stored stores values that have been stored in memory, bound to
	// FreeVars or passed as Parameterse.
	stored map[ssa.Value]ssa.Value

	// used is a temporary map, used only for valueAsString. It prevents
	// multiple use of the same memory location.
	used map[ssa.Value]struct{}

	// refs indicates the number of references on this structure. If it's
	// greater than one, we will do copy-on-write.
	refs *int32
}

// newLockState makes a new lockState.
func newLockState() *lockState {
	refs := int32(1) // Not shared.
	return &lockState{
		mutexes: make(map[string]lockType),
		used:    make(map[ssa.Value]struct{}),
		stored:  make(map[ssa.Value]ssa.Value),
		refs:    &refs,
	}
}

// fork forks the locking state. When a lockState is forked, any modifications
// will cause maps to be copied.
func (l *lockState) fork() *lockState {
	if l == nil {
		return newLockState()
	}
	atomic.AddInt32(l.refs, 1)
	return &lockState{
		mutexes: l.mutexes,
		used:    make(map[ssa.Value]struct{}),
		stored:  l.stored,
		refs:    l.refs,
	}
}

// modify indicates that this state will be modified.
func (l *lockState) modify() {
	if atomic.LoadInt32(l.refs) > 1 {
		// Copy the lockedMutexes.
		lm := make(map[string]lockType)
		for k, v := range l.mutexes {
			lm[k] = v
		}
		l.mutexes = lm

		// Copy the stored values.
		s := make(map[ssa.Value]ssa.Value)
		for k, v := range l.stored {
			s[k] = v
		}
		l.stored = s

		// Reset the used values.
		l.used = make(map[ssa.Value]struct{})

		// Drop our reference.
		atomic.AddInt32(l.refs, -1)
		newRefs := int32(1) // Not shared.
		l.refs = &newRefs
	}
}

// isHeld indicates whether the field is held is not.
func (l *lockState) isHeld(rv resolvedValue) (string, bool) {
	if !rv.valid {
		return rv.valueAsString(l), false
	}
	s := rv.valueAsString(l)

	state := l.mutexes[s]
	return s, state.isLocked()
}

// lockField locks the given field.
//
// If false is returned, the field was already locked.
func (l *lockState) lockField(rv resolvedValue) (string, bool) {
	if !rv.valid {
		return rv.valueAsString(l), false
	}
	s := rv.valueAsString(l)

	if state := l.mutexes[s]; state.isLocked() {
		return s, false
	} else {
		l.modify()
		l.mutexes[s] = state.lock()
		return s, true
	}
}

// unlockField unlocks the given field.
//
// If false is returned, the field was not locked.
func (l *lockState) unlockField(rv resolvedValue) (string, bool) {
	if !rv.valid {
		return rv.valueAsString(l), false
	}
	s := rv.valueAsString(l)

	state := l.mutexes[s]
	if state.isUnlocked() {
		return s, false
	}

	l.modify()
	if notLocked := state.unlock(); notLocked == unlocked {
		delete(l.mutexes, s) // s goes back to unlocked.
	} else {
		l.mutexes[s] = notLocked
	}

	return s, true
}

// deferUnlockField records a deferred unlock call.
//
// If false is returned, the unlock has been already deferred.
func (l *lockState) deferUnlockField(rv resolvedValue) (string, bool) {
	if !rv.valid {
		return rv.valueAsString(l), false
	}
	s := rv.valueAsString(l)

	if state := l.mutexes[s]; state.hasDeferredUnlock() {
		return s, false
	} else {
		l.modify()
		l.mutexes[s] = state.deferUnlock()
		return s, true
	}
}

// store records an alias.
func (l *lockState) store(addr ssa.Value, v ssa.Value) {
	l.modify()
	l.stored[addr] = v
}

// isSubset indicates other holds all the locks held by l.
func (l *lockState) isSubset(other *lockState) bool {
	held := 0 // Number in l, held by other.
	for k, lockType := range l.mutexes {
		if lockType.isLocked() && lockType == other.mutexes[k] {
			held++
		}
	}
	return held >= l.numLocksHeld()
}

// numLocksHeld indicates the number of locks held.
func (l *lockState) numLocksHeld() int {
	held := 0
	for _, lockType := range l.mutexes {
		if lockType.isLocked() {
			held++
		}
	}
	return held
}

// isCompatible returns true if the states hold the same locks.
// The nil state is the lock superset and is compatible with any other
// lock state.
func (l *lockState) isCompatible(other *lockState) bool {
	if l == nil || other == nil {
		return true
	}
	return l.isSubset(other) && other.isSubset(l)
}

// join returns a new lockState of the intersection of 2 states.
func (l *lockState) join(other *lockState) *lockState {
	if l == nil {
		return other
	} else if other == nil {
		return l
	}

	rls := l.fork()

	// Take the intersection of stored elements
	for addr, val := range rls.stored {
		if oval, ok := other.stored[addr]; !ok || val != oval {
			rls.modify()
			// TODO(jmesyou): Does it make sense to delete elements? Should we keep an extra info?
			delete(rls.stored, addr)
		}
	}

	// Take the intersection of locked mutexes
	for k, lockType := range rls.mutexes {
		if lockType == other.mutexes[k] {
			continue
		}

		rls.modify()
		delete(rls.mutexes, k)
	}

	return rls
}

// elemType is a type that implements the Elem function.
type elemType interface {
	Elem() types.Type
}

// valueAsString returns a string for a given value.
//
// This decomposes the value into the simplest possible representation in terms
// of parameters, free variables and globals. During resolution, stored values
// may be transferred, as well as bound free variables.
//
// Nil may not be passed here.
func (l *lockState) valueAsString(v ssa.Value) string {
	switch x := v.(type) {
	case *ssa.Parameter:
		// Was this provided as a paramter for a local anonymous
		// function invocation?
		v, ok := l.stored[x]
		if ok {
			return l.valueAsString(v)
		}
		return fmt.Sprintf("{param:%s}", x.Name())
	case *ssa.Global:
		return fmt.Sprintf("{global:%s}", x.Name())
	case *ssa.FreeVar:
		// Attempt to resolve this, in case we are being invoked in a
		// scope where all the variables are bound.
		v, ok := l.stored[x]
		if ok {
			// The FreeVar is typically bound to a location, so we
			// check what's been stored there. Note that the second
			// may map to the same FreeVar, which we can check.
			stored, ok := l.stored[v]
			if ok {
				return l.valueAsString(stored)
			}
		}
		return fmt.Sprintf("{freevar:%s}", x.Name())
	case *ssa.Convert:
		// Just disregard conversion.
		return l.valueAsString(x.X)
	case *ssa.ChangeType:
		// Ditto, disregard.
		return l.valueAsString(x.X)
	case *ssa.UnOp:
		if x.Op != token.MUL {
			break
		}
		// Is this loading a free variable? If yes, then this can be
		// resolved in the original isAlias function.
		if fv, ok := x.X.(*ssa.FreeVar); ok {
			return l.valueAsString(fv)
		}
		// Should be try to resolve via a memory address? This needs to
		// be done since a memory location can hold its own value.
		if _, ok := l.used[x.X]; !ok {
			// Check if we know what the accessed location holds.
			// This is used to disambiguate memory locations.
			v, ok := l.stored[x.X]
			if ok {
				l.used[x.X] = struct{}{}
				defer func() { delete(l.used, x.X) }()
				return l.valueAsString(v)
			}
		}
		// x.X.Type is pointer. We must construct this type
		// dynamically, since the ssa.Value could be synthetic.
		return fmt.Sprintf("*(%s)", l.valueAsString(x.X))
	case *ssa.Field:
		structType, ok := resolveStruct(x.X.Type())
		if !ok {
			// This should not happen.
			panic(fmt.Sprintf("structType not available for struct: %#v", x.X))
		}
		fieldObj := structType.Field(x.Field)
		return fmt.Sprintf("%s.%s", l.valueAsString(x.X), fieldObj.Name())
	case *ssa.FieldAddr:
		structType, ok := resolveStruct(x.X.Type())
		if !ok {
			// This should not happen.
			panic(fmt.Sprintf("structType not available for struct: %#v", x.X))
		}
		fieldObj := structType.Field(x.Field)
		return fmt.Sprintf("&(%s.%s)", l.valueAsString(x.X), fieldObj.Name())
	case *ssa.Index:
		return fmt.Sprintf("%s[%s]", l.valueAsString(x.X), l.valueAsString(x.Index))
	case *ssa.IndexAddr:
		return fmt.Sprintf("&(%s[%s])", l.valueAsString(x.X), l.valueAsString(x.Index))
	case *ssa.Lookup:
		return fmt.Sprintf("%s[%s]", l.valueAsString(x.X), l.valueAsString(x.Index))
	case *ssa.Extract:
		return fmt.Sprintf("%s[%d]", l.valueAsString(x.Tuple), x.Index)
	}

	// In the case of any other type (e.g. this may be an alloc, a return
	// value, etc.), just return the literal pointer value to the Value.
	// This will be unique within the ssa graph, and so if two values are
	// equal, they are from the same type.
	return fmt.Sprintf("{%T:%p}", v, v)
}

// String returns the full lock state.
func (l *lockState) String() string {
	if l.numLocksHeld() == 0 {
		return "no locks held"
	}

	var locksHeld []string
	for k, lockType := range l.mutexes {
		if lockType.isLocked() {
			locksHeld = append(locksHeld, k)
		}
	}
	// sort for comparing results
	sort.Strings(locksHeld)

	return strings.Join(locksHeld, ",")
}

// resolveDeferredUnlocks symbolically executes earlier `defer *.Unlock()` statements on
// the lock state. This function is called in checkInstruction when a ssa.RunDefers is
// encountered.
func (l *lockState) resolveDeferredUnlocks() (string, bool) {
	for k, lockType := range l.mutexes {
		if lockType.hasDeferredUnlock() {
			// lock `k` is already unlocked, but there is also a deferred unlock
			// return the invalid mutex name.
			return k, false
		}
	}
	for k, lockType := range l.mutexes {
		if lockType.isLocked() && lockType.hasDeferredUnlock() {
			l.modify()
			delete(l.mutexes, k) // k goes back to unlocked.
		}
	}

	return "", true
}
