package api

import "net/http"

// This file is compiled only when testing package api, so nothing here reaches
// the shipped binary. It exists so the external api_test package can exercise
// the *assembled* middleware stack — the real ordering, the real Recovery, the
// real error rendering — against a handler that misbehaves on purpose.
//
// The alternative, rebuilding an equivalent chain inside the test, would test a
// copy of the ordering rather than the ordering the server actually uses, and
// would therefore keep passing after someone reorders buildRouter.

// RegisterTestRoute adds a route wrapped in the server's global middleware.
func (s *Server) RegisterTestRoute(method, pattern string, h http.HandlerFunc) {
	s.router.Handle(method, pattern, h)
}
