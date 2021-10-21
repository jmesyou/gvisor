package test

func testGuessedLockedAccessValid(tc *guessedGuardStruct) {
	tc.mu.Lock()
	tc.guardedField = 1
	tc.mu.Unlock()
}

func testGuessedLockedAccessInvalid(tc *guessedGuardStruct) {
	tc.guardedField = 1 // +checklocksfail
}

func testGuessedNoLockAccessValid(tc *guessedGuardNoGuardStruct) {
	tc.unguardedField = 1
}

// TODO(jamesyou): more tests
