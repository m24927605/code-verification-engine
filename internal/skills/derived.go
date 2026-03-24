package skills

import (
	"sort"
	"strings"

	"github.com/verabase/code-verification-engine/internal/rules"
)

func deriveSkills(signals []Signal) []string {
	seen := make(map[string]bool)
	for _, s := range signals {
		if s.Status == StatusUnsupported || s.SkillID == "" {
			continue
		}
		seen[s.SkillID] = true
	}
	return sortedKeys(seen)
}

func deriveLanguages(languages []string) []string {
	seen := make(map[string]bool)
	for _, lang := range languages {
		lang = strings.TrimSpace(lang)
		if lang == "" {
			continue
		}
		seen[lang] = true
	}
	return sortedKeys(seen)
}

func deriveTechnologies(fs *rules.FactSet) []Technology {
	if fs == nil {
		return nil
	}

	seen := make(map[string]Technology)
	for _, imp := range fs.Imports {
		if tech, ok := inferTechnologyFromImport(imp.ImportPath); ok {
			seen[tech.Kind+":"+tech.Name] = tech
		}
	}
	for _, mw := range fs.Middlewares {
		if tech, ok := inferTechnologyFromMiddlewareKind(mw.Kind); ok {
			seen[tech.Kind+":"+tech.Name] = tech
		}
	}
	for _, da := range fs.DataAccess {
		if tech, ok := inferTechnologyFromDataBackend(da.Backend); ok {
			seen[tech.Kind+":"+tech.Name] = tech
		}
	}

	out := make([]Technology, 0, len(seen))
	for _, tech := range seen {
		out = append(out, tech)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Name < out[j].Name
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func deriveFrameworks(technologies []Technology) []string {
	var out []string
	for _, tech := range technologies {
		if tech.Kind == "framework" {
			out = append(out, tech.Name)
		}
	}
	sort.Strings(out)
	return out
}

func inferTechnologyFromImport(path string) (Technology, bool) {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "github.com/gin-gonic/gin"):
		return Technology{Name: "gin", Kind: "framework"}, true
	case strings.Contains(p, "github.com/labstack/echo"):
		return Technology{Name: "echo", Kind: "framework"}, true
	case strings.Contains(p, "fastapi"):
		return Technology{Name: "fastapi", Kind: "framework"}, true
	case strings.Contains(p, "@nestjs/"):
		return Technology{Name: "nestjs", Kind: "framework"}, true
	case strings.Contains(p, "express"):
		return Technology{Name: "express", Kind: "framework"}, true
	case strings.Contains(p, "fastify"):
		return Technology{Name: "fastify", Kind: "framework"}, true
	case strings.Contains(p, "@hapi/hapi") || p == "hapi":
		return Technology{Name: "hapi", Kind: "framework"}, true
	case p == "koa" || strings.Contains(p, "/koa"):
		return Technology{Name: "koa", Kind: "framework"}, true
	case strings.Contains(p, "next/") || p == "next":
		return Technology{Name: "nextjs", Kind: "framework"}, true
	case strings.HasPrefix(p, "react-router"):
		return Technology{Name: "react-router", Kind: "router"}, true
	case strings.HasPrefix(p, "vue-router"):
		return Technology{Name: "vue-router", Kind: "router"}, true
	case p == "react" || p == "react-dom":
		return Technology{Name: "react", Kind: "library"}, true
	case p == "vue":
		return Technology{Name: "vue", Kind: "library"}, true
	case strings.Contains(p, "django"):
		return Technology{Name: "django", Kind: "framework"}, true
	case strings.Contains(p, "flask"):
		return Technology{Name: "flask", Kind: "framework"}, true
	case strings.Contains(p, "prisma"):
		return Technology{Name: "prisma", Kind: "orm"}, true
	case strings.Contains(p, "typeorm"):
		return Technology{Name: "typeorm", Kind: "orm"}, true
	case strings.Contains(p, "sequelize"):
		return Technology{Name: "sequelize", Kind: "orm"}, true
	case strings.Contains(p, "mongoose"):
		return Technology{Name: "mongoose", Kind: "orm"}, true
	case p == "pg":
		return Technology{Name: "pg", Kind: "database_driver"}, true
	case strings.Contains(p, "helmet"):
		return Technology{Name: "helmet", Kind: "middleware_package"}, true
	case p == "cors" || strings.Contains(p, "/cors"):
		return Technology{Name: "cors", Kind: "middleware_package"}, true
	}
	return Technology{}, false
}

func inferTechnologyFromMiddlewareKind(kind string) (Technology, bool) {
	switch strings.ToLower(kind) {
	case "express":
		return Technology{Name: "express", Kind: "framework"}, true
	case "fastify-plugin":
		return Technology{Name: "fastify", Kind: "framework"}, true
	case "hapi-plugin":
		return Technology{Name: "hapi", Kind: "framework"}, true
	case "fastapi_depends":
		return Technology{Name: "fastapi", Kind: "framework"}, true
	default:
		return Technology{}, false
	}
}

func inferTechnologyFromDataBackend(backend string) (Technology, bool) {
	b := strings.ToLower(backend)
	switch {
	case strings.Contains(b, "prisma"):
		return Technology{Name: "prisma", Kind: "orm"}, true
	case strings.Contains(b, "typeorm"):
		return Technology{Name: "typeorm", Kind: "orm"}, true
	case strings.Contains(b, "sequelize"):
		return Technology{Name: "sequelize", Kind: "orm"}, true
	case strings.Contains(b, "mongoose"):
		return Technology{Name: "mongoose", Kind: "orm"}, true
	case b == "postgres" || b == "postgresql":
		return Technology{Name: "postgresql", Kind: "database"}, true
	case b == "mysql":
		return Technology{Name: "mysql", Kind: "database"}, true
	case b == "mongodb":
		return Technology{Name: "mongodb", Kind: "database"}, true
	default:
		return Technology{}, false
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
