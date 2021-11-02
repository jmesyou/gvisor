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

func testGuessedAndAnnotatedValid(tc *guessedAndAnnotatedGuardStruct) {
	tc.mu.Lock()
	tc.guardedField = 1
	tc.annotatedGuardField = 2
	tc.mu.Unlock()
	tc.unguardedField = 3
}

func testGuessedAndAnnotatedInvalid(tc *guessedAndAnnotatedGuardStruct) {
	tc.guardedField = 1        // +checklocksfail
	tc.annotatedGuardField = 2 // +checkslockfail
}

// TODO(jamesyou): more tests
