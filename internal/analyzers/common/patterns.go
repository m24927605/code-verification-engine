package common

import (
	"regexp"
	"strings"
)

// Exported Python regex patterns for use by structural extractors.
// These are defined here (in common) so the structural_extract.go file
// can apply them on structurally-filtered source without importing the
// python analyzer package (which would create a circular dependency).
var (
	fromImportReExported    = regexp.MustCompile(`^from\s+(\S+)\s+import\s+(.+)`)
	importReExported        = regexp.MustCompile(`^import\s+(.+)`)
	fastapiRouteReExported  = regexp.MustCompile(`@\w+\.(get|post|put|delete|patch)\s*\(\s*"([^"]+)"`)
	flaskRouteReExported    = regexp.MustCompile(`@\w+\.route\s*\(\s*"([^"]+)"`)
	secretAssignReExported  = regexp.MustCompile(`(?i)^(\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|CREDENTIAL|DATABASE_URL)\w*)\s*=\s*["']([^"']+)["']`)
)

var (
	esImportRe      = regexp.MustCompile(`^import\s+(?:type\s+)?(?:(?:\{[^}]*\}|\*\s+as\s+\w+|\w+)\s+from\s+)?['"]([^'"]+)['"]`)
	requireImportRe = regexp.MustCompile(`(?:const|let|var)\s+(?:\{[^}]*\}|\w+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	expressRouteRe  = regexp.MustCompile(`(?:app|router|\w+Router)\.(get|post|put|patch|delete|options|head)\(\s*['"]([^'"]+)['"]`)
	funcDeclRe      = regexp.MustCompile(`^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)`)
	arrowFuncRe     = regexp.MustCompile(`^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(`)
	classDeclRe     = regexp.MustCompile(`^(?:export\s+)?(?:abstract\s+)?class\s+(\w+)`)
	interfaceDeclRe = regexp.MustCompile(`^(?:export\s+)?interface\s+(\w+)`)
	middlewareRe     = regexp.MustCompile(`(?:app|router)\.use\(\s*(\w+)`)
	exportKeywordRe = regexp.MustCompile(`^export\s+`)
	exportsObjRe    = regexp.MustCompile(`^(?:module\.)?exports[\.\[= ]`)

	// Data access patterns
	prismaRe    = regexp.MustCompile(`(\w+\.\w+\.(?:findMany|findUnique|findFirst|create|update|delete|upsert|count|aggregate|groupBy))`)
	pgQueryRe   = regexp.MustCompile(`(\w+\.query)\(`)
	sequelizeRe = regexp.MustCompile(`(\w+\.(?:findAll|findOne|findByPk|bulkCreate))\(`)
	mongoRe     = regexp.MustCompile(`(\w+\.collection)\(`)
	typeormRe   = regexp.MustCompile(`(\w+\.(?:getRepository|createQueryBuilder))\(`)

	// Secret patterns
	secretKeyRe = regexp.MustCompile(`(?i)(?:const|let|var)\s+\w*(?:secret|token|jwt_secret|auth_secret)\w*\s*=\s*["']([^"']{8,})["']`)
	passwordRe  = regexp.MustCompile(`(?i)(?:const|let|var)\s+\w*(?:password|passwd|pwd)\w*\s*=\s*["']([^"']{4,})["']`)
	apiKeyRe    = regexp.MustCompile(`(?i)(?:const|let|var)\s+\w*(?:api_key|apikey|api_secret)\w*\s*=\s*["']([^"']{8,})["']`)

	// Browser storage patterns (localStorage/sessionStorage)
	localStorageSetRe   = regexp.MustCompile(`(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\s*\(`)
	localStorageDirectRe = regexp.MustCompile(`(localStorage|sessionStorage)\s*\[`)

	// NestJS patterns
	nestControllerRe = regexp.MustCompile(`@Controller\s*\(\s*['"]([^'"]*)['"]`)
	nestRouteRe      = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch)\s*\(\s*['"]?([^'")\s]*)`)
	nestGuardRe      = regexp.MustCompile(`@UseGuards\s*\(\s*(\w+)`)
	nestInterceptorRe = regexp.MustCompile(`@UseInterceptors\s*\(\s*(\w+)`)
	nestInjectRepoRe  = regexp.MustCompile(`@InjectRepository\s*\(\s*(\w+)`)

	// NestJS enableCors detection
	nestEnableCorsRe = regexp.MustCompile(`(?:app|server)\s*\.\s*enableCors\s*\(`)
	nestCorsOriginRe = regexp.MustCompile(`origin\s*:\s*(true|'\*'|"\*")`)

	// NestJS provider registration (APP_INTERCEPTOR, APP_FILTER, APP_GUARD, APP_PIPE)
	nestAppProviderRe  = regexp.MustCompile(`(?:APP_INTERCEPTOR|APP_FILTER|APP_GUARD|APP_PIPE)`)
	nestGlobalUseRe    = regexp.MustCompile(`(?:useGlobalInterceptors|useGlobalFilters|useGlobalGuards|useGlobalPipes)\s*\(`)
	nestConsumerApplyRe = regexp.MustCompile(`consumer\s*\.\s*apply\s*\(`)
	nestConfigureRe     = regexp.MustCompile(`configure\s*\(\s*consumer`)

	// NestJS validation pipe
	nestValidationPipeRe = regexp.MustCompile(`ValidationPipe`)

	// Drizzle ORM
	drizzleRe = regexp.MustCompile(`(drizzle)\s*\(`)

	// Fastify patterns
	fastifyRouteRe    = regexp.MustCompile(`fastify\.(get|post|put|delete|patch|options)\s*\(\s*['"]([^'"]+)['"]`)
	fastifyRouteObjRe = regexp.MustCompile(`\.route\s*\(\s*\{[^}]*url:\s*['"]([^'"]+)['"]`)
	fastifyRegisterRe = regexp.MustCompile(`fastify\.register\s*\(\s*(\w+)`)
	fastifyHookRe     = regexp.MustCompile(`fastify\.addHook\s*\(\s*['"](\w+)['"]`)

	// Koa patterns (router.get etc. — expressRouteRe already matches \w+Router but not plain "router")
	koaRouteRe = regexp.MustCompile(`router\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`)

	// Hapi patterns
	hapiRouteRe      = regexp.MustCompile(`server\.route\s*\(`)
	hapiRoutePathRe  = regexp.MustCompile(`path:\s*['"]([^'"]+)['"]`)
	hapiRouteMethodRe = regexp.MustCompile(`method:\s*['"](\w+)['"]`)
	hapiExtRe        = regexp.MustCompile(`server\.ext\s*\(\s*['"](\w+)['"]`)
	hapiRegisterRe   = regexp.MustCompile(`server\.register\s*\(\s*(\w+)`)

	// Next.js API route file path patterns
	nextPagesAPIRe = regexp.MustCompile(`(?:^|/)(?:src/)?pages/api/(.+)\.[jt]sx?$`)
	nextAppAPIRe   = regexp.MustCompile(`(?:^|/)(?:src/)?app/api/(.+)/route\.[jt]sx?$`)
	// Next.js exported HTTP method names
	nextExportMethodRe = regexp.MustCompile(`^export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b`)
)

// MatchESImport returns the import path from an ES import statement, or "".
func MatchESImport(line string) string {
	m := esImportRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// MatchRequireImport returns the module path from a require() call, or "".
func MatchRequireImport(line string) string {
	m := requireImportRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// MatchExpressRoute returns (METHOD, path) from Express-style route, or ("","").
func MatchExpressRoute(line string) (string, string) {
	m := expressRouteRe.FindStringSubmatch(line)
	if m != nil {
		return toUpperMethod(m[1]), m[2]
	}
	return "", ""
}

func toUpperMethod(s string) string {
	switch s {
	case "get":
		return "GET"
	case "post":
		return "POST"
	case "put":
		return "PUT"
	case "patch":
		return "PATCH"
	case "delete":
		return "DELETE"
	case "options":
		return "OPTIONS"
	case "head":
		return "HEAD"
	default:
		return s
	}
}

// MatchSymbolDecl returns (name, kind) from a function/class/interface declaration, or ("","").
func MatchSymbolDecl(line string) (string, string) {
	if m := funcDeclRe.FindStringSubmatch(line); m != nil {
		return m[1], "function"
	}
	if m := arrowFuncRe.FindStringSubmatch(line); m != nil {
		return m[1], "function"
	}
	if m := classDeclRe.FindStringSubmatch(line); m != nil {
		return m[1], "class"
	}
	if m := interfaceDeclRe.FindStringSubmatch(line); m != nil {
		return m[1], "interface"
	}
	return "", ""
}

// MatchExpressMiddleware returns the middleware name from app.use()/router.use(), or "".
func MatchExpressMiddleware(line string) string {
	m := middlewareRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// MatchDataAccess returns (operation, backend) for known data access patterns, or ("","").
func MatchDataAccess(line string) (string, string) {
	if m := prismaRe.FindStringSubmatch(line); m != nil {
		return m[1], "prisma"
	}
	if m := pgQueryRe.FindStringSubmatch(line); m != nil {
		return m[1], "pg"
	}
	if m := mongoRe.FindStringSubmatch(line); m != nil {
		return m[1], "mongodb"
	}
	if m := typeormRe.FindStringSubmatch(line); m != nil {
		return m[1], "typeorm"
	}
	if m := sequelizeRe.FindStringSubmatch(line); m != nil {
		return m[1], "sequelize"
	}
	return "", ""
}

// MatchSecret returns the kind of hardcoded secret detected, or "".
func MatchSecret(line string) string {
	if apiKeyRe.MatchString(line) {
		return "hardcoded_api_key"
	}
	if passwordRe.MatchString(line) {
		return "hardcoded_password"
	}
	if secretKeyRe.MatchString(line) {
		return "hardcoded_secret"
	}
	return ""
}

// IsExported returns true if the line starts with export or uses module.exports/exports.
func IsExported(line string) bool {
	return exportKeywordRe.MatchString(line) || exportsObjRe.MatchString(line)
}

// --- NestJS ---

// ExtractNestController returns the route prefix from @Controller('prefix'), or "".
func ExtractNestController(line string) string {
	m := nestControllerRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// ExtractNestRoute returns (method, path, ok) from @Get('/path') etc.
func ExtractNestRoute(line string) (string, string, bool) {
	m := nestRouteRe.FindStringSubmatch(line)
	if m != nil {
		return toUpperMethod(strings.ToLower(m[1])), m[2], true
	}
	return "", "", false
}

// ExtractNestGuard returns the guard name from @UseGuards(Guard), or "".
func ExtractNestGuard(line string) string {
	m := nestGuardRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// ExtractNestInterceptor returns the interceptor name from @UseInterceptors(X), or "".
func ExtractNestInterceptor(line string) string {
	m := nestInterceptorRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// ExtractNestInjectRepo returns the entity name from @InjectRepository(Entity), or "".
func ExtractNestInjectRepo(line string) string {
	m := nestInjectRepoRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// --- Fastify ---

// ExtractFastifyRoute returns (method, path, ok) from fastify.get('/path', ...).
func ExtractFastifyRoute(line string) (string, string, bool) {
	m := fastifyRouteRe.FindStringSubmatch(line)
	if m != nil {
		return toUpperMethod(m[1]), m[2], true
	}
	return "", "", false
}

// ExtractFastifyRouteObj returns the url from fastify.route({ url: '/path' }), or "".
func ExtractFastifyRouteObj(line string) string {
	m := fastifyRouteObjRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// ExtractFastifyRegister returns the plugin name from fastify.register(plugin), or "".
func ExtractFastifyRegister(line string) string {
	m := fastifyRegisterRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// ExtractFastifyHook returns the hook name from fastify.addHook('onRequest', ...), or "".
func ExtractFastifyHook(line string) string {
	m := fastifyHookRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// --- Koa ---

// ExtractKoaRoute returns (method, path, ok) from router.get('/path', ...).
func ExtractKoaRoute(line string) (string, string, bool) {
	m := koaRouteRe.FindStringSubmatch(line)
	if m != nil {
		return toUpperMethod(m[1]), m[2], true
	}
	return "", "", false
}

// --- Hapi ---

// ExtractHapiRoute returns (method, path, ok) from server.route({ method: 'GET', path: '/x' }).
func ExtractHapiRoute(line string) (string, string, bool) {
	if !hapiRouteRe.MatchString(line) {
		return "", "", false
	}
	pm := hapiRoutePathRe.FindStringSubmatch(line)
	mm := hapiRouteMethodRe.FindStringSubmatch(line)
	if pm != nil && mm != nil {
		return toUpperMethod(strings.ToLower(mm[1])), pm[1], true
	}
	return "", "", false
}

// ExtractHapiExt returns the extension point from server.ext('onPreHandler', ...), or "".
func ExtractHapiExt(line string) string {
	m := hapiExtRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// ExtractHapiRegister returns the plugin name from server.register(plugin), or "".
func ExtractHapiRegister(line string) string {
	m := hapiRegisterRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// --- Next.js ---

// IsNextAPIRoute checks if the file path is a Next.js API route and returns the route path.
func IsNextAPIRoute(filePath string) (string, bool) {
	// Normalize to forward slashes
	fp := strings.ReplaceAll(filePath, "\\", "/")

	if m := nextPagesAPIRe.FindStringSubmatch(fp); m != nil {
		route := convertNextPathToRoute(m[1])
		return "/api/" + route, true
	}
	if m := nextAppAPIRe.FindStringSubmatch(fp); m != nil {
		route := convertNextPathToRoute(m[1])
		return "/api/" + route, true
	}
	return "", false
}

// MatchNextExportMethod returns an HTTP method name from "export function GET()" etc., or "".
func MatchNextExportMethod(line string) string {
	m := nextExportMethodRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// MatchBrowserStorageAccess returns (storageType, method) for localStorage/sessionStorage usage, or ("","").
// storageType is "localStorage" or "sessionStorage", method is "setItem", "getItem", or "removeItem".
func MatchBrowserStorageAccess(line string) (string, string) {
	m := localStorageSetRe.FindStringSubmatch(line)
	if m != nil {
		return m[1], m[2]
	}
	m = localStorageDirectRe.FindStringSubmatch(line)
	if m != nil {
		return m[1], "bracket_access"
	}
	return "", ""
}

// MatchNestEnableCors returns true if the line contains app.enableCors() or similar.
func MatchNestEnableCors(line string) bool {
	return nestEnableCorsRe.MatchString(line)
}

// MatchNestCorsPermissive returns true if the CORS config has origin: true or origin: '*'.
func MatchNestCorsPermissive(line string) bool {
	return nestCorsOriginRe.MatchString(line)
}

// MatchNestAppProvider returns true if the line references APP_INTERCEPTOR, APP_FILTER, etc.
func MatchNestAppProvider(line string) bool {
	return nestAppProviderRe.MatchString(line)
}

// MatchNestGlobalUse returns true if the line contains useGlobalInterceptors/Filters/etc.
func MatchNestGlobalUse(line string) bool {
	return nestGlobalUseRe.MatchString(line)
}

// MatchNestConsumerApply returns true if the line contains consumer.apply(...).
func MatchNestConsumerApply(line string) bool {
	return nestConsumerApplyRe.MatchString(line)
}

// MatchNestConfigure returns true if the line contains configure(consumer...).
func MatchNestConfigure(line string) bool {
	return nestConfigureRe.MatchString(line)
}

// MatchNestValidationPipe returns true if the line references ValidationPipe.
func MatchNestValidationPipe(line string) bool {
	return nestValidationPipeRe.MatchString(line)
}

// MatchDrizzle returns the operation from drizzle() call, or "".
func MatchDrizzle(line string) string {
	m := drizzleRe.FindStringSubmatch(line)
	if m != nil {
		return m[1]
	}
	return ""
}

// convertNextPathToRoute converts a Next.js file path segment to a route path.
// e.g. "users/[id]/index" -> "users/:id"
func convertNextPathToRoute(seg string) string {
	// Remove trailing /index
	seg = strings.TrimSuffix(seg, "/index")
	if seg == "index" {
		return ""
	}
	// Convert [param] to :param and [...param] to :param*
	parts := strings.Split(seg, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, "[...") && strings.HasSuffix(p, "]") {
			parts[i] = ":" + p[4:len(p)-1] + "*"
		} else if strings.HasPrefix(p, "[[...") && strings.HasSuffix(p, "]]") {
			parts[i] = ":" + p[5:len(p)-2] + "*"
		} else if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") {
			parts[i] = ":" + p[1:len(p)-1]
		}
	}
	return strings.Join(parts, "/")
}
