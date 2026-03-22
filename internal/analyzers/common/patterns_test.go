package common_test

import (
	"testing"

	"github.com/verabase/code-verification-engine/internal/analyzers/common"
)

func TestMatchESImport(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`import express from 'express';`, "express"},
		{`import { Router } from 'express';`, "express"},
		{`import * as jwt from 'jsonwebtoken';`, "jsonwebtoken"},
		{`import type { Request } from 'express';`, "express"},
		{`import cors from 'cors';`, "cors"},
		{`import { PrismaClient } from '@prisma/client';`, "@prisma/client"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.MatchESImport(tt.line)
		if got != tt.want {
			t.Errorf("MatchESImport(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestMatchRequireImport(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`const express = require('express');`, "express"},
		{`const { Pool } = require('pg');`, "pg"},
		{`var jwt = require("jsonwebtoken");`, "jsonwebtoken"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.MatchRequireImport(tt.line)
		if got != tt.want {
			t.Errorf("MatchRequireImport(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestMatchExpressRoute(t *testing.T) {
	tests := []struct {
		line   string
		method string
		path   string
	}{
		{`router.get('/api/users', getUsers);`, "GET", "/api/users"},
		{`app.post("/api/login", handleLogin);`, "POST", "/api/login"},
		{`router.delete('/items/:id', deleteItem);`, "DELETE", "/items/:id"},
		{`itemsRouter.get('/', async (req, res) => {`, "GET", "/"},
		{`const x = 1;`, "", ""},
	}
	for _, tt := range tests {
		m, p := common.MatchExpressRoute(tt.line)
		if m != tt.method || p != tt.path {
			t.Errorf("MatchExpressRoute(%q) = (%q,%q), want (%q,%q)", tt.line, m, p, tt.method, tt.path)
		}
	}
}

func TestMatchSymbolDecl(t *testing.T) {
	tests := []struct {
		line string
		name string
		kind string
	}{
		{`function getUsers(req, res) {`, "getUsers", "function"},
		{`async function handleLogin(req, res) {`, "handleLogin", "function"},
		{`const getUsers = (req, res) => {`, "getUsers", "function"},
		{`const getUsers = async (req, res) => {`, "getUsers", "function"},
		{`export function getUsers() {`, "getUsers", "function"},
		{`export default function main() {`, "main", "function"},
		{`class UserController {`, "UserController", "class"},
		{`export class AuthService {`, "AuthService", "class"},
		{`interface UserInput {`, "UserInput", "interface"},
		{`export interface AuthConfig {`, "AuthConfig", "interface"},
		{`const x = 1;`, "", ""},
	}
	for _, tt := range tests {
		n, k := common.MatchSymbolDecl(tt.line)
		if n != tt.name || k != tt.kind {
			t.Errorf("MatchSymbolDecl(%q) = (%q,%q), want (%q,%q)", tt.line, n, k, tt.name, tt.kind)
		}
	}
}

func TestMatchExpressMiddleware(t *testing.T) {
	tests := []struct {
		line string
		name string
	}{
		{`app.use(cors());`, "cors"},
		{`app.use(authMiddleware);`, "authMiddleware"},
		{`router.use(validateToken);`, "validateToken"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.MatchExpressMiddleware(tt.line)
		if got != tt.name {
			t.Errorf("MatchExpressMiddleware(%q) = %q, want %q", tt.line, got, tt.name)
		}
	}
}

func TestMatchDataAccess(t *testing.T) {
	tests := []struct {
		line      string
		operation string
		backend   string
	}{
		{`await prisma.user.findMany();`, "prisma.user.findMany", "prisma"},
		{`const result = await pool.query('SELECT * FROM users');`, "pool.query", "pg"},
		{`await db.collection('users').find({})`, "db.collection", "mongodb"},
		{`const x = 1;`, "", ""},
	}
	for _, tt := range tests {
		op, be := common.MatchDataAccess(tt.line)
		if op != tt.operation || be != tt.backend {
			t.Errorf("MatchDataAccess(%q) = (%q,%q), want (%q,%q)", tt.line, op, be, tt.operation, tt.backend)
		}
	}
}

func TestMatchSecret(t *testing.T) {
	tests := []struct {
		line string
		kind string
	}{
		{`const JWT_SECRET = "mysecretkey123456";`, "hardcoded_secret"},
		{`const password = "admin123";`, "hardcoded_password"},
		{`const API_KEY = "sk-abc123def456ghi";`, "hardcoded_api_key"},
		{`const dbUrl = process.env.DATABASE_URL;`, ""},
	}
	for _, tt := range tests {
		got := common.MatchSecret(tt.line)
		if got != tt.kind {
			t.Errorf("MatchSecret(%q) = %q, want %q", tt.line, got, tt.kind)
		}
	}
}

func TestIsExported(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{`export function getUsers() {`, true},
		{`export class AuthService {`, true},
		{`export default function main() {`, true},
		{`exports.getUsers = getUsers;`, true},
		{`module.exports = router;`, true},
		{`function getUsers() {`, false},
		{`class AuthService {`, false},
	}
	for _, tt := range tests {
		got := common.IsExported(tt.line)
		if got != tt.want {
			t.Errorf("IsExported(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

// --- NestJS ---

func TestExtractNestController(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`@Controller('users')`, "users"},
		{`@Controller("items")`, "items"},
		{`@Controller('api/v1/products')`, "api/v1/products"},
		{`@Controller('')`, ""},
		{`class UserController {`, ""},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractNestController(tt.line)
		if got != tt.want {
			t.Errorf("ExtractNestController(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestExtractNestRoute(t *testing.T) {
	tests := []struct {
		line   string
		method string
		path   string
		ok     bool
	}{
		{`@Get('/users')`, "GET", "/users", true},
		{`@Post('/users')`, "POST", "/users", true},
		{`@Put('/users/:id')`, "PUT", "/users/:id", true},
		{`@Delete('/users/:id')`, "DELETE", "/users/:id", true},
		{`@Patch('/users/:id')`, "PATCH", "/users/:id", true},
		{`@Get()`, "GET", "", true},
		{`const x = 1;`, "", "", false},
	}
	for _, tt := range tests {
		m, p, ok := common.ExtractNestRoute(tt.line)
		if m != tt.method || p != tt.path || ok != tt.ok {
			t.Errorf("ExtractNestRoute(%q) = (%q,%q,%v), want (%q,%q,%v)", tt.line, m, p, ok, tt.method, tt.path, tt.ok)
		}
	}
}

func TestExtractNestGuard(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`@UseGuards(AuthGuard)`, "AuthGuard"},
		{`@UseGuards(JwtAuthGuard)`, "JwtAuthGuard"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractNestGuard(tt.line)
		if got != tt.want {
			t.Errorf("ExtractNestGuard(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestExtractNestInterceptor(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`@UseInterceptors(CacheInterceptor)`, "CacheInterceptor"},
		{`@UseInterceptors(LoggingInterceptor)`, "LoggingInterceptor"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractNestInterceptor(tt.line)
		if got != tt.want {
			t.Errorf("ExtractNestInterceptor(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestExtractNestInjectRepo(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`@InjectRepository(User)`, "User"},
		{`@InjectRepository(OrderEntity)`, "OrderEntity"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractNestInjectRepo(tt.line)
		if got != tt.want {
			t.Errorf("ExtractNestInjectRepo(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// --- Fastify ---

func TestExtractFastifyRoute(t *testing.T) {
	tests := []struct {
		line   string
		method string
		path   string
		ok     bool
	}{
		{`fastify.get('/api/users', handler)`, "GET", "/api/users", true},
		{`fastify.post('/api/users', handler)`, "POST", "/api/users", true},
		{`fastify.put('/api/users/:id', handler)`, "PUT", "/api/users/:id", true},
		{`fastify.delete('/api/users/:id', handler)`, "DELETE", "/api/users/:id", true},
		{`fastify.patch('/api/users/:id', handler)`, "PATCH", "/api/users/:id", true},
		{`fastify.options('/api/users', handler)`, "OPTIONS", "/api/users", true},
		{`const x = 1;`, "", "", false},
	}
	for _, tt := range tests {
		m, p, ok := common.ExtractFastifyRoute(tt.line)
		if m != tt.method || p != tt.path || ok != tt.ok {
			t.Errorf("ExtractFastifyRoute(%q) = (%q,%q,%v), want (%q,%q,%v)", tt.line, m, p, ok, tt.method, tt.path, tt.ok)
		}
	}
}

func TestExtractFastifyRouteObj(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`.route({ url: '/api/items', method: 'GET' })`, "/api/items"},
		{`.route({ method: 'POST', url: "/api/items" })`, "/api/items"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractFastifyRouteObj(tt.line)
		if got != tt.want {
			t.Errorf("ExtractFastifyRouteObj(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestExtractFastifyRegister(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`fastify.register(cors)`, "cors"},
		{`fastify.register(userRoutes)`, "userRoutes"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractFastifyRegister(tt.line)
		if got != tt.want {
			t.Errorf("ExtractFastifyRegister(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestExtractFastifyHook(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`fastify.addHook('onRequest', handler)`, "onRequest"},
		{`fastify.addHook("preSerialization", handler)`, "preSerialization"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractFastifyHook(tt.line)
		if got != tt.want {
			t.Errorf("ExtractFastifyHook(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// --- Koa ---

func TestExtractKoaRoute(t *testing.T) {
	tests := []struct {
		line   string
		method string
		path   string
		ok     bool
	}{
		{`router.get('/users', listUsers)`, "GET", "/users", true},
		{`router.post('/users', createUser)`, "POST", "/users", true},
		{`router.put('/users/:id', updateUser)`, "PUT", "/users/:id", true},
		{`router.delete('/users/:id', deleteUser)`, "DELETE", "/users/:id", true},
		{`router.patch('/users/:id', patchUser)`, "PATCH", "/users/:id", true},
		{`const x = 1;`, "", "", false},
	}
	for _, tt := range tests {
		m, p, ok := common.ExtractKoaRoute(tt.line)
		if m != tt.method || p != tt.path || ok != tt.ok {
			t.Errorf("ExtractKoaRoute(%q) = (%q,%q,%v), want (%q,%q,%v)", tt.line, m, p, ok, tt.method, tt.path, tt.ok)
		}
	}
}

// --- Hapi ---

func TestExtractHapiRoute(t *testing.T) {
	tests := []struct {
		line   string
		method string
		path   string
		ok     bool
	}{
		{`server.route({ method: 'GET', path: '/users' })`, "GET", "/users", true},
		{`server.route({ method: 'POST', path: '/users' })`, "POST", "/users", true},
		{`server.route({ method: 'PUT', path: '/users/{id}' })`, "PUT", "/users/{id}", true},
		{`server.route({ method: 'DELETE', path: '/users/{id}' })`, "DELETE", "/users/{id}", true},
		// no match: missing server.route(
		{`{ method: 'GET', path: '/users' }`, "", "", false},
		// no match: has server.route but missing path/method
		{`server.route({ handler: fn })`, "", "", false},
		{`const x = 1;`, "", "", false},
	}
	for _, tt := range tests {
		m, p, ok := common.ExtractHapiRoute(tt.line)
		if m != tt.method || p != tt.path || ok != tt.ok {
			t.Errorf("ExtractHapiRoute(%q) = (%q,%q,%v), want (%q,%q,%v)", tt.line, m, p, ok, tt.method, tt.path, tt.ok)
		}
	}
}

func TestExtractHapiExt(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`server.ext('onPreHandler', handler)`, "onPreHandler"},
		{`server.ext("onPostAuth", handler)`, "onPostAuth"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractHapiExt(tt.line)
		if got != tt.want {
			t.Errorf("ExtractHapiExt(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

func TestExtractHapiRegister(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`server.register(Inert)`, "Inert"},
		{`server.register(authPlugin)`, "authPlugin"},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.ExtractHapiRegister(tt.line)
		if got != tt.want {
			t.Errorf("ExtractHapiRegister(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// --- Next.js ---

func TestIsNextAPIRoute(t *testing.T) {
	tests := []struct {
		filePath string
		route    string
		ok       bool
	}{
		// Pages router
		{"pages/api/users.js", "/api/users", true},
		{"pages/api/users.ts", "/api/users", true},
		{"src/pages/api/users.ts", "/api/users", true},
		{"pages/api/users/index.ts", "/api/users", true},
		{"pages/api/users/[id].ts", "/api/users/:id", true},
		{"pages/api/posts/[...slug].ts", "/api/posts/:slug*", true},
		{"pages/api/posts/[[...slug]].ts", "/api/posts/:slug*", true},
		// App router
		{"app/api/users/route.ts", "/api/users", true},
		{"src/app/api/users/route.ts", "/api/users", true},
		{"app/api/users/[id]/route.ts", "/api/users/:id", true},
		{"app/api/posts/[...slug]/route.ts", "/api/posts/:slug*", true},
		{"app/api/posts/[[...slug]]/route.tsx", "/api/posts/:slug*", true},
		// Not API routes
		{"pages/users.ts", "", false},
		{"app/users/page.ts", "", false},
		{"src/components/Button.tsx", "", false},
		{`const x = 1;`, "", false},
		// Backslash normalization (Windows-style)
		{`pages\api\users.ts`, "/api/users", true},
	}
	for _, tt := range tests {
		route, ok := common.IsNextAPIRoute(tt.filePath)
		if route != tt.route || ok != tt.ok {
			t.Errorf("IsNextAPIRoute(%q) = (%q,%v), want (%q,%v)", tt.filePath, route, ok, tt.route, tt.ok)
		}
	}
}

func TestMatchNextExportMethod(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`export function GET() {`, "GET"},
		{`export function POST(request) {`, "POST"},
		{`export function PUT(request) {`, "PUT"},
		{`export function DELETE(request) {`, "DELETE"},
		{`export function PATCH(request) {`, "PATCH"},
		{`export function HEAD() {`, "HEAD"},
		{`export function OPTIONS() {`, "OPTIONS"},
		{`export async function GET() {`, "GET"},
		{`export async function POST(request) {`, "POST"},
		// No match
		{`function GET() {`, ""},
		{`export function getUsers() {`, ""},
		{`const x = 1;`, ""},
	}
	for _, tt := range tests {
		got := common.MatchNextExportMethod(tt.line)
		if got != tt.want {
			t.Errorf("MatchNextExportMethod(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}

// --- Additional coverage for toUpperMethod via MatchExpressRoute ---

func TestMatchExpressRouteOptionsHead(t *testing.T) {
	tests := []struct {
		line   string
		method string
		path   string
	}{
		{`app.options('/api/cors', handler)`, "OPTIONS", "/api/cors"},
		{`app.head('/api/ping', handler)`, "HEAD", "/api/ping"},
	}
	for _, tt := range tests {
		m, p := common.MatchExpressRoute(tt.line)
		if m != tt.method || p != tt.path {
			t.Errorf("MatchExpressRoute(%q) = (%q,%q), want (%q,%q)", tt.line, m, p, tt.method, tt.path)
		}
	}
}

// --- Additional MatchDataAccess coverage for typeorm and sequelize ---

func TestMatchDataAccessTypeORMSequelize(t *testing.T) {
	tests := []struct {
		line      string
		operation string
		backend   string
	}{
		{`const repo = manager.getRepository(User)`, "manager.getRepository", "typeorm"},
		{`const qb = conn.createQueryBuilder(User)`, "conn.createQueryBuilder", "typeorm"},
		{`const users = await User.findAll()`, "User.findAll", "sequelize"},
		{`const user = await User.findOne({ where: { id } })`, "User.findOne", "sequelize"},
		{`const user = await User.findByPk(1)`, "User.findByPk", "sequelize"},
		{`await User.bulkCreate(records)`, "User.bulkCreate", "sequelize"},
	}
	for _, tt := range tests {
		op, be := common.MatchDataAccess(tt.line)
		if op != tt.operation || be != tt.backend {
			t.Errorf("MatchDataAccess(%q) = (%q,%q), want (%q,%q)", tt.line, op, be, tt.operation, tt.backend)
		}
	}
}
