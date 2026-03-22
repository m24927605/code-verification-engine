#!/usr/bin/env python3
"""Extract facts from Python source using the ast module.

Usage: python3 ast_extract.py <filepath>

Outputs JSON to stdout. Handles syntax errors gracefully.
No non-stdlib imports.
"""

import ast
import json
import re
import sys
import os


SECRET_PATTERN = re.compile(
    r"(?i)^(\w*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|CREDENTIAL|DATABASE_URL)\w*)$"
)


def extract_facts(source, filename="<stdin>"):
    result = {
        "imports": [],
        "symbols": [],
        "routes": [],
        "middlewares": [],
        "data_access": [],
        "secrets": [],
        "classes": [],
        "error": None,
    }

    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as e:
        result["error"] = f"SyntaxError: {e}"
        return result

    _extract_imports(tree, result)
    _extract_symbols(tree, result, source)
    _extract_routes_and_middleware(tree, result)
    _extract_data_access(tree, result, source)
    _extract_secrets(tree, result, source)
    _extract_classes(tree, result)

    return result


def _extract_imports(tree, result):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                result["imports"].append({
                    "module": alias.name,
                    "names": [],
                    "alias": alias.asname or "",
                    "line": node.lineno,
                })
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [a.name for a in node.names] if node.names else []
            alias = ""
            # If single import with alias, capture it
            if len(node.names) == 1 and node.names[0].asname:
                alias = node.names[0].asname
            result["imports"].append({
                "module": module,
                "names": names,
                "alias": alias,
                "line": node.lineno,
            })


def _extract_symbols(tree, result, source):
    # Annotate parent references so we can distinguish methods from functions
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child._parent = node

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end_line = getattr(node, "end_lineno", node.lineno)
            parent = getattr(node, "_parent", None)
            if isinstance(parent, ast.ClassDef):
                result["symbols"].append({
                    "name": node.name,
                    "kind": "method",
                    "line": node.lineno,
                    "end_line": end_line,
                    "exported": not node.name.startswith("_"),
                    "parent_class": parent.name,
                })
            else:
                result["symbols"].append({
                    "name": node.name,
                    "kind": "function",
                    "line": node.lineno,
                    "end_line": end_line,
                    "exported": not node.name.startswith("_"),
                })
        elif isinstance(node, ast.ClassDef):
            end_line = getattr(node, "end_lineno", node.lineno)
            result["symbols"].append({
                "name": node.name,
                "kind": "class",
                "line": node.lineno,
                "end_line": end_line,
                "exported": not node.name.startswith("_"),
            })


def _get_decorator_info(decorator):
    """Extract method and path from a route decorator."""
    # @app.get("/path"), @router.post("/path"), etc.
    if isinstance(decorator, ast.Call):
        func = decorator.func
        if isinstance(func, ast.Attribute):
            method_name = func.attr.lower()
            http_methods = {"get", "post", "put", "delete", "patch"}
            if method_name in http_methods:
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    return method_name.upper(), str(decorator.args[0].value)
            elif method_name == "route":
                # Flask @app.route("/path")
                if decorator.args and isinstance(decorator.args[0], ast.Constant):
                    # Check for methods= keyword
                    return "ANY", str(decorator.args[0].value)
    return None, None


def _extract_routes_and_middleware(tree, result):
    depends_refs = set()

    for node in ast.walk(tree):
        # Route decorators on functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Collect per-route dependencies from function signature
            route_deps = _extract_route_dependencies(node)
            # Collect non-route decorator names (e.g., @login_required)
            non_route_decorators = _extract_non_route_decorators(node)
            route_middlewares = list(route_deps) + non_route_decorators

            for dec in node.decorator_list:
                method, path = _get_decorator_info(dec)
                if method and path:
                    # Also extract dependencies= keyword from route decorator
                    dep_names = _extract_decorator_dependencies(dec)
                    all_mw = route_middlewares + dep_names
                    entry = {
                        "method": method,
                        "path": path,
                        "handler": node.name,
                        "line": dec.lineno,
                    }
                    if all_mw:
                        entry["middlewares"] = all_mw
                    result["routes"].append(entry)

        # Depends() calls anywhere
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "Depends":
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Name):
                        depends_refs.add((arg.id, node.lineno))
            # add_middleware() calls
            if isinstance(func, ast.Attribute) and func.attr == "add_middleware":
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Name):
                        result["middlewares"].append({
                            "name": arg.id,
                            "framework": "starlette",
                            "line": node.lineno,
                        })
            # before_request() calls — Flask global middleware
            if isinstance(func, ast.Attribute) and func.attr == "before_request":
                # @app.before_request is used as a decorator, so we look at
                # decorated functions instead. But app.before_request(fn) as a
                # direct call also exists.
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Name):
                        result["middlewares"].append({
                            "name": arg.id,
                            "framework": "flask_before_request",
                            "line": node.lineno,
                        })

        # @app.before_request decorator on functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Attribute) and dec.attr == "before_request":
                    result["middlewares"].append({
                        "name": node.name,
                        "framework": "flask_before_request",
                        "line": dec.lineno,
                    })

    for name, line in depends_refs:
        result["middlewares"].append({
            "name": name,
            "framework": "fastapi_depends",
            "line": line,
        })


def _find_enclosing_func(tree, lineno):
    """Find the enclosing function/method for a given line number."""
    # Annotate parents if not already done
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            if not hasattr(child, "_parent"):
                child._parent = node

    best = None
    best_size = float("inf")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            if start <= lineno <= end:
                size = end - start
                if size < best_size:
                    best_size = size
                    best = node
    if best is None:
        return None, None
    parent = getattr(best, "_parent", None)
    if isinstance(parent, ast.ClassDef):
        return best.name, "method"
    return best.name, "function"


def _extract_data_access(tree, result, source):
    has_sqlalchemy = False
    has_psycopg2 = False
    has_django_orm = False
    has_tortoise = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("sqlalchemy"):
                    has_sqlalchemy = True
                if alias.name.startswith("psycopg2"):
                    has_psycopg2 = True
                if alias.name.startswith("tortoise"):
                    has_tortoise = True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("sqlalchemy"):
                has_sqlalchemy = True
            if mod.startswith("psycopg2"):
                has_psycopg2 = True
            if mod.startswith("django.db"):
                has_django_orm = True
            if mod.startswith("tortoise"):
                has_tortoise = True

    if has_sqlalchemy:
        # Look for Session usage
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in ("Session", "session"):
                caller, caller_kind = _find_enclosing_func(tree, node.lineno)
                entry = {
                    "operation": "session",
                    "backend": "sqlalchemy",
                    "line": node.lineno,
                }
                if caller:
                    entry["caller"] = caller
                    entry["caller_kind"] = caller_kind
                result["data_access"].append(entry)
                break
            if isinstance(node, ast.Attribute) and node.attr in ("Session", "session"):
                caller, caller_kind = _find_enclosing_func(tree, node.lineno)
                entry = {
                    "operation": "session",
                    "backend": "sqlalchemy",
                    "line": node.lineno,
                }
                if caller:
                    entry["caller"] = caller
                    entry["caller_kind"] = caller_kind
                result["data_access"].append(entry)
                break

    if has_psycopg2:
        result["data_access"].append({
            "operation": "cursor",
            "backend": "psycopg2",
            "line": 1,
        })

    if has_django_orm:
        # Look for .objects.filter() etc
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    op = func.attr
                    if op in ("filter", "get", "create", "all", "exclude", "update",
                              "delete", "aggregate", "annotate"):
                        # Check if it's .objects.X
                        val = func.value
                        if isinstance(val, ast.Attribute) and val.attr == "objects":
                            caller, caller_kind = _find_enclosing_func(tree, node.lineno)
                            entry = {
                                "operation": op,
                                "backend": "django-orm",
                                "line": node.lineno,
                            }
                            if caller:
                                entry["caller"] = caller
                                entry["caller_kind"] = caller_kind
                            result["data_access"].append(entry)

    if has_tortoise:
        result["data_access"].append({
            "operation": "query",
            "backend": "tortoise",
            "line": 1,
        })


def _extract_secrets(tree, result, source):
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if SECRET_PATTERN.match(var_name):
                        # Must be a string constant (hardcoded)
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            # Skip os.environ / os.getenv
                            line_text = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                            if "os.environ" in line_text or "os.getenv" in line_text:
                                continue
                            if var_name.upper() == "DEBUG":
                                continue
                            result["secrets"].append({
                                "name": var_name,
                                "line": node.lineno,
                            })
                        elif isinstance(node.value, ast.Call):
                            # e.g. os.environ.get(...) - skip these
                            pass


def _extract_classes(tree, result):
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            bases = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    bases.append(base.id)
                elif isinstance(base, ast.Attribute):
                    bases.append(ast.dump(base).replace("Attribute", "").replace("(", "").replace(")", ""))
                    # Just use a simpler representation
                    parts = []
                    n = base
                    while isinstance(n, ast.Attribute):
                        parts.append(n.attr)
                        n = n.value
                    if isinstance(n, ast.Name):
                        parts.append(n.id)
                    parts.reverse()
                    bases[-1] = ".".join(parts)

            methods = []
            for item in ast.iter_child_nodes(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.append(item.name)

            end_line = getattr(node, "end_lineno", node.lineno)
            result["classes"].append({
                "name": node.name,
                "line": node.lineno,
                "end_line": end_line,
                "bases": bases,
                "methods": methods,
            })


def _extract_route_dependencies(func_node):
    """Extract Depends() names from function parameter defaults."""
    deps = []
    for default in func_node.args.defaults:
        name = _extract_depends_name(default)
        if name:
            deps.append(name)
    for default in func_node.args.kw_defaults:
        if default is not None:
            name = _extract_depends_name(default)
            if name:
                deps.append(name)
    return deps


def _extract_depends_name(node):
    """Extract the dependency name from a Depends(func) call."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "Depends":
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    return arg.id
    return None


def _extract_non_route_decorators(func_node):
    """Extract non-route decorator names (e.g., @login_required)."""
    names = []
    for dec in func_node.decorator_list:
        # Skip route decorators (app.get, router.post, etc.)
        method, path = _get_decorator_info(dec)
        if method and path:
            continue
        # Simple decorator: @login_required
        if isinstance(dec, ast.Name):
            names.append(dec.id)
        # Decorator with args: @require_role("admin")
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                names.append(dec.func.id)
    return names


def _extract_decorator_dependencies(decorator):
    """Extract dependency names from dependencies= keyword in route decorators."""
    deps = []
    if not isinstance(decorator, ast.Call):
        return deps
    for kw in decorator.keywords:
        if kw.arg == "dependencies":
            if isinstance(kw.value, ast.List):
                for elt in kw.value.elts:
                    name = _extract_depends_name(elt)
                    if name:
                        deps.append(name)
    return deps


def main():
    if len(sys.argv) < 2:
        source = sys.stdin.read()
        filename = "<stdin>"
    else:
        filepath = sys.argv[1]
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
            filename = filepath
        except IOError as e:
            json.dump({"error": str(e)}, sys.stdout)
            sys.exit(0)

    result = extract_facts(source, filename)
    json.dump(result, sys.stdout, indent=None, separators=(",", ":"))


if __name__ == "__main__":
    main()
