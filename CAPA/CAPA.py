import os
import string
from collections import defaultdict
from pathlib import Path

import capa.engine
import capa.main
import capa.render.result_document as rd
import capa.version
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Result,
    ResultOrderedKeyValueSection,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from capa.render.default import find_subrule_matches
from capa.render.utils import capability_rules
from capa.rules import InvalidRule, InvalidRuleSet


def safely_get_param(request: ServiceRequest, param, default):
    param_value = default
    try:
        param_value = request.get_param(param)
    except Exception:
        pass
    return param_value


class CAPA(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)

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
        self.rule_paths = [Path(os.path.join(os.path.dirname(__file__), "capa-rules-6.1.0"))]

        try:
            # Ruleset downloaded from https://github.com/mandiant/capa-rules/archive/refs/tags/v6.1.0.zip
            self.rules = capa.main.get_rules(self.rule_paths)
            self.log.info("successfully loaded %s rules", len(self.rules))
        except (IOError, InvalidRule, InvalidRuleSet) as e:
            self.log.error("InvalidRuleSet: %s", str(e))
            return -1

        try:
            # Ruleset downloaded from https://github.com/fireeye/capa/tree/v6.1.0/sigs
            self.sig_paths = capa.main.get_signatures(Path(os.path.join(os.path.dirname(__file__), "sigs")))
        except (IOError) as e:
            self.log.error("InvalidSignatureSet: %s", str(e))
            return -1

    def get_capa_results(self, request: ServiceRequest, rules, sigpaths, format, path):
        # Parts taken from https://github.com/mandiant/capa/blob/master/scripts/bulk-process.py
        should_save_workspace = os.environ.get("CAPA_SAVE_WORKSPACE") not in ("0", "no", "NO", "n", None)
        self.log.debug("Getting capa extractor for: %s", path)
        try:
            extractor = capa.main.get_extractor(
                Path(path),
                format,
                capa.main.OS_AUTO,
                capa.main.BACKEND_VIV,
                sigpaths,
                should_save_workspace,
                disable_progress=True,
            )
        except capa.main.UnsupportedFormatError as e:
            self.log.error("UnsupportedFormatError: %s", str(e))
            return {
                "path": path,
                "status": "error",
                "error": "input file does not appear to be a PE file: %s" % path,
            }
        except capa.main.UnsupportedRuntimeError as e:
            self.log.error("UnsupportedRuntimeError: %s", str(e))
            return {
                "path": path,
                "status": "error",
                "error": "unsupported runtime or Python interpreter",
            }
        except Exception as e:
            if request.file_type == "executable/windows/dos" or request.task.mime != "application/x-dosexec":
                self.log.debug("Exception (dos file): %s", str(e))
            else:
                self.log.error("Exception: %s", str(e))
            return {
                "path": path,
                "status": "error",
                "error": "unexpected error: %s" % (e),
            }

        meta = capa.main.collect_metadata([], Path(path), format, capa.main.OS_AUTO, self.rule_paths, extractor)
        self.log.debug("Getting capa capabilities")
        capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
        meta.analysis.feature_counts = counts['feature_counts']
        meta.analysis.library_functions = counts['library_functions']
        meta.analysis.layout = capa.main.compute_layout(rules, extractor, capabilities)
        self.log.debug("Got capa capabilities")

        file_limitation_rules = list(filter(capa.main.is_file_limitation_rule, rules.rules.values()))
        for file_limitation_rule in file_limitation_rules:
            if file_limitation_rule.name not in capabilities:
                continue

            res = ResultSection(f"File Limitation - {file_limitation_rule.name}")
            res.add_line(file_limitation_rule.meta.get("description", ""))
            request.result.add_section(res)
            break

        doc = rd.ResultDocument.from_capa(meta, rules, capabilities)

        renderer = safely_get_param(request, "renderer", "default")
        if renderer == "simple":
            self.simple_view(request, capabilities)
        elif renderer == "verbose":
            self.render_rules(request, doc)
        else:
            self.default_view(request, doc)

    def default_view(self, request, doc: rd.ResultDocument):
        tactics = defaultdict(set)
        objectives = defaultdict(set)
        caps = []
        subrule_matches = find_subrule_matches(doc)
        for rule in capability_rules(doc):
            for attack in rule.meta.attack:
                tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id))
            for mbc in rule.meta.mbc:
                objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id))
            if rule.meta.name not in subrule_matches:
                count = len(rule.matches)
                if count == 1:
                    capability = rule.meta.name
                else:
                    capability = f"{rule.meta.name} ({count} matches)"
                caps.append((capability, rule.meta.namespace if rule.meta.namespace else ""))

        self.render_attack(request, tactics)
        self.render_mbc(request, objectives)
        self.render_capabilities(request, caps)

    def render_attack(self, request, tactics):
        added = False
        res = ResultTableSection("ATT&CK")
        res.set_heuristic(1)
        for tactic, techniques in sorted(tactics.items()):
            for (technique, subtechnique, id) in sorted(techniques):
                res.add_row(
                    TableRow(
                        {
                            "ATT&CK Tactic": tactic.upper(),
                            "ATT&CK Technique": technique if not subtechnique else f"{technique} ({subtechnique})",
                            "ATT&CK ID": id,
                        }
                    )
                )
                res.heuristic.add_attack_id(id)
                added = True
        if added:
            request.result.add_section(res)

    def render_mbc(self, request, objectives):
        added = False
        res = ResultTableSection("Malware Behavior Catalog")
        for objective, behaviors in sorted(objectives.items()):
            for (behavior, method, id) in sorted(behaviors):
                res.add_row(
                    TableRow(
                        {
                            "MBC Objective": objective.upper(),
                            "MBC Behavior": behavior if not method else f"{behavior} ({method})",
                            "MBC ID": id,
                        }
                    )
                )
                added = True
        if added:
            request.result.add_section(res)

    def render_capabilities(self, request, caps):
        added = False
        res = ResultTableSection("Capabilities")
        for cap, namespace in sorted(caps):
            res.add_row(
                TableRow(
                    {
                        "Capability": cap,
                        "Namespace": namespace,
                    }
                )
            )
            added = True
        if added:
            request.result.add_section(res)

    def simple_view(self, request, capabilities):
        def remove_hash_ending(rule_name):
            if len(rule_name) > 33 and rule_name[-33] == "/" and all(c in string.hexdigits for c in rule_name[-32:]):
                return remove_hash_ending(rule_name[:-33])
            return rule_name

        capa_graph_data = list(set([remove_hash_ending(x) for x in capabilities.keys()]))

        res = ResultSection("CAPA Information")
        res.add_lines(capa_graph_data)

        request.result.add_section(res)

    def render_rules(self, request, doc: rd.ResultDocument):
        # See https://github.com/mandiant/capa/blob/v6.1.0/capa/render/vverbose.py#L281
        for _, _, rule in sorted((rule.meta.namespace or "", rule.meta.name, rule) for rule in doc.rules.values()):
            if rule.meta.is_subscope_rule:
                continue

            count = len(rule.matches)
            if count == 1:
                capability = rule.meta.name
            else:
                capability = f"{rule.meta.name} ({count} matches)"

            res = ResultOrderedKeyValueSection(capability)

            res.add_item("namespace", rule.meta.namespace if rule.meta.namespace else "")

            if rule.meta.maec.analysis_conclusion or rule.meta.maec.analysis_conclusion_ov:
                res.add_item(
                    "maec/analysis-conclusion",
                    rule.meta.maec.analysis_conclusion or rule.meta.maec.analysis_conclusion_ov,
                )

            if rule.meta.maec.malware_family:
                res.add_item("maec/malware-family", rule.meta.maec.malware_family)

            if rule.meta.maec.malware_category or rule.meta.maec.malware_category_ov:
                res.add_item(
                    "maec/malware-category", rule.meta.maec.malware_category or rule.meta.maec.malware_category_ov
                )

            if rule.meta.description:
                res.add_item("description", rule.meta.description)

            if rule.meta.attack:
                res.set_heuristic(1)
                [res.heuristic.add_attack_id(data.id) for data in rule.meta.attack]
                res.add_item(
                    "att&ck", ", ".join(["%s [%s]" % ("::".join(data.parts), data.id) for data in rule.meta.attack])
                )

            if rule.meta.mbc:
                res.add_item("mbc", ", ".join(["%s [%s]" % ("::".join(data.parts), data.id) for data in rule.meta.mbc]))

            request.result.add_section(res)

    def execute(self, request):
        request.result = Result()

        if request.file_size > self.config.get("max_file_size", 512000):
            return

        self.get_capa_results(request, self.rules, self.sig_paths, "auto", request.file_path)

    def get_tool_version(self):
        return capa.version.__version__
