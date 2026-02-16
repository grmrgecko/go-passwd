# go-passwd

This project is a Go library for password hashing and verification, designed to be compatible with `libcrypt` standards.

# Code Style Guidelines

- Write pragmatic, systems-oriented Go focused on correctness and clarity.
- Favor explicit control flow and simple data structures over abstraction.
- Use short, consistent receiver names.
- Exported names are clear and descriptive; internal helpers are lowerCamelCase.
- Return errors when callers can act; otherwise log and continue safely.
- Log operational details at debug level, lifecycle events at info, and failures at error level.
- Avoid panics, hidden side effects, and over-engineering.
- Comments are functional and intent-focused, explaining why something exists or what role it plays.
- Exported types and methods have short, direct doc comments that describe responsibility.
- Comments are operational in tone, written for someone maintaining or debugging the system.
- Inline comments are brief and precise, explaining non-obvious logic or marking logical phases of a function.
- Functions with multiple logical steps use short section comments to label each phase (e.g. "Validate input.", "Persist to database.", "Build response.").
- No conversational language, jokes, or speculative notes—comments are concise and purposeful.
- The code is expected to remain readable without comments; comments add clarity where reasoning is not immediately obvious.
- The name of the element (func, struct, var, ect) being commented should be the first word in the comment.
- Comments are expected to be a complete sentence with ending notation such as a period. We are humans with proper english.
