import os
import string

import capa
import capa.main
import capa.render.json
import capa.rules
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection


class CAPA(ServiceBase):
    def __init__(self, config=None):
        super(CAPA, self).__init__(config)

    def start(self):
        # capa does not declare a __str__ or a __repr__ for that special object, so without the following, we get
        #   "<capa.engine.Result object at 0x7f17da579880>"
        # in the ResultSection if we want to use the full capabilities report
        capa.engine.Result.__repr__ = lambda self: (
            f"{self.__class__.__module__}.{self.__class__.__qualname__}("
            f"success={self.success}, "
            f"statement: {self.statement}, "
            f"children: {self.children}, "
            f"locations: {self.locations}"
            ")"
        )

        try:
            # Ruleset downloaded from https://github.com/fireeye/capa-rules/tree/v3.0.2
            rules_path = capa.main.get_rules(
                os.path.join(os.path.dirname(__file__), "capa-rules-3.0.2"),
                disable_progress=True,
            )
            self.rules = capa.rules.RuleSet(rules_path)
            self.log.info("successfully loaded %s rules", len(self.rules))
        except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
            self.log.error("%s", str(e))
            return -1

        try:
            # Ruleset downloaded from https://github.com/fireeye/capa/tree/v3.0.2/sigs
            self.sig_paths = capa.main.get_signatures(os.path.join(os.path.dirname(__file__), "sigs"))
        except (IOError) as e:
            self.log.error("%s", str(e))
            return -1

    def get_capa_results(self, rules, sigpaths, format, path):
        # Taken mostly from https://github.com/fireeye/capa/blob/master/scripts/bulk-process.py
        should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)
        self.log.info("Getting capa extractor for: %s", path)
        try:
            extractor = capa.main.get_extractor(
                path,
                format,
                capa.main.BACKEND_VIV,
                sigpaths,
                should_save_workspace,
                disable_progress=True,
            )
        except capa.main.UnsupportedFormatError as e:
            self.log.error("%s", str(e))
            return {
                "path": path,
                "status": "error",
                "error": "input file does not appear to be a PE file: %s" % path,
            }
        except capa.main.UnsupportedRuntimeError as e:
            self.log.error("%s", str(e))
            return {
                "path": path,
                "status": "error",
                "error": "unsupported runtime or Python interpreter",
            }
        except Exception as e:
            self.log.error("%s", str(e))
            return {
                "path": path,
                "status": "error",
                "error": "unexpected error: %s" % (e),
            }

        self.log.info("Getting capa capabilities")
        capabilities, _ = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        self.log.info("Got capa capabilities")

        def ends_with_subscope_rule(rule_name):
            return len(rule_name) > 33 and rule_name[-33] == "/" and all(c in string.hexdigits for c in rule_name[-32:])

        return list(set([x[:-33] if ends_with_subscope_rule(x) else x for x in capabilities.keys()]))

    def execute(self, request):
        request.result = Result()
        self.file_res = request.result
        self.path = request.file_path
        self.request = request

        capa_graph_data = self.get_capa_results(self.rules, self.sig_paths, "pe", self.path)

        res = ResultSection("CAPA Information")
        for element in capa_graph_data:
            res.add_line(element)
        self.file_res.add_section(res)
