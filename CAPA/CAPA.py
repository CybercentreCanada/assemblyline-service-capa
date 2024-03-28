import argparse
import os
import string
from collections import defaultdict

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
        self.parser = argparse.ArgumentParser(description="detect capabilities in programs.")
        capa.main.install_common_args(
            self.parser, wanted={"rules", "signatures", "format", "os", "backend", "input_file"}
        )
        self.argv = [
            "--quiet",
            "--signatures",
            os.path.join(os.path.dirname(__file__), "sigs"),
            "--rules",
            os.path.join(os.path.dirname(__file__), "capa-rules-7.0.1"),
            "--format",
            "auto",
            "--backend",
            "auto",
            "--os",
            "auto",
        ]

    def get_capa_results(self, request: ServiceRequest, input_file):
        # Mostly taken from https://github.com/mandiant/capa/blob/v7.0.1/scripts/bulk-process.py
        argv = self.argv + [input_file]
        args = self.parser.parse_args(args=argv)

        try:
            capa.main.handle_common_args(args)
            capa.main.ensure_input_exists_from_cli(args)
            input_format = capa.main.get_input_format_from_cli(args)
            rules = capa.main.get_rules_from_cli(args)
            backend = capa.main.get_backend_from_cli(args, input_format)
            sample_path = capa.main.get_sample_path_from_cli(args, backend)
            if sample_path is None:
                os_ = "unknown"
            else:
                os_ = capa.loader.get_os(sample_path)
            extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
        except capa.main.ShouldExitError as e:
            return {"path": input_file, "status": "error", "error": str(e), "status_code": e.status_code}
        except Exception as e:
            return {
                "path": input_file,
                "status": "error",
                "error": f"unexpected error: {e}",
            }
        capabilities, counts = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)

        meta = capa.loader.collect_metadata(argv, args.input_file, "auto", os_, [], extractor, counts)
        meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities)

        doc = rd.ResultDocument.from_capa(meta, rules, capabilities)

        renderer = safely_get_param(request, "renderer", "default")
        if renderer == "simple":
            self.simple_view(request, capabilities)
        elif renderer == "verbose":
            self.render_rules(request, doc)
        else:
            self.default_view(request, doc)

        return {"path": input_file, "status": "ok", "ok": doc.model_dump()}

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
            for technique, subtechnique, id in sorted(techniques):
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
            for behavior, method, id in sorted(behaviors):
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

        request.set_service_context(f"CAPA {self.get_tool_version()}")

        result = self.get_capa_results(request, request.file_path)
        if result["status"] == "error":
            self.log.error(result["error"])
        elif result["status"] == "ok":
            pass
            # doc = rd.ResultDocument.model_validate(result["ok"]).model_dump_json(exclude_none=True)
        else:
            raise ValueError(f"unexpected status: {result['status']}")

    def get_tool_version(self):
        return capa.version.__version__
