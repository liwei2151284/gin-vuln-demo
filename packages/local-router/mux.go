// Package mux is a local stub replacing gorilla/mux v1.7.x.
// Pinned via go.mod replace directive — no version hash recorded in go.sum.
// Code in this directory can be modified freely without any version control.
// [SCA场景七] 版本约束宽松：replace 本地路径完全脱离版本管控
package mux

import "net/http"

type Router struct{}

func NewRouter() *Router { return &Router{} }

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {}
