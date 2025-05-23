import ida_kernwin
import ida_funcs
import idaapi
import idautils
import idc
import ida_hexrays
import ida_name
import ida_lines
import ida_bytes
import ida_segment

import threading
import requests
import json
import re
import logging
from functools import partial

# ==================== CONFIGURATION ====================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

GEMINI_API_KEY = "YOUR_API_KEY_HERE"
GEMINI_API_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
CONFIDENCE_THRESHOLD = 0.7
REQUEST_TIMEOUT = 45
TEMPERATURE = 0.3

GENERIC_FUNC_PREFIXES = ["sub_", "func_"]
GENERIC_LABEL_PREFIXES = ["loc_", "off_", "unk_", "byte_", "word_", "dword_", "qword_"]

LOCAL_ASM_LINES_BEFORE = 5
LOCAL_ASM_LINES_AFTER = 15

print("Gem Plugin Loading...")

# ==================== CLASSES ====================
class GemAPIClient:
    def __init__(self):
        self.api_key = GEMINI_API_KEY

    def _make_api_request(self, prompt: str) -> dict:
            #Make API request to Gemini
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            logging.error("Gemini API key not configured")
            ida_kernwin.warning("Please set your Gemini API key in the plugin file!")
            return None

        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": TEMPERATURE,
                "maxOutputTokens": 1024
            }
        }

        try:
            url = f"{GEMINI_API_ENDPOINT}?key={self.api_key}"
            response = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)

            if response.status_code == 200:
                result = response.json()
                if "candidates" in result and len(result["candidates"]) > 0:
                    content_part = result["candidates"][0].get("content", {}).get("parts", [{}])[0]
                    if "text" in content_part:
                        return self._parse_response(content_part["text"])
                    else:
                        logging.error(f"Gemini API Error: Unexpected response structure - 'text' missing. Response: {result}")
                else:
                    logging.error(f"Gemini API Error: No candidates in response. Response: {result}")
            else:
                logging.error(f"Gemini API Error: {response.status_code} - {response.text}")

        except requests.exceptions.Timeout:
            logging.error(f"Error calling Gemini API: Request timed out after {REQUEST_TIMEOUT} seconds.")
        except Exception as e:
            logging.error(f"Error calling Gemini API: {str(e)}")
        return None

    def analyze_function(self, func_info: dict) -> dict:
        # Send function information to Gemini for analysis
        prompt = self._create_function_analysis_prompt(func_info)
        return self._make_api_request(prompt)

    def analyze_local_label(self, label_info: dict) -> dict:
        # Send local label information to Gemini for analysis
        prompt = self._create_local_label_analysis_prompt(label_info)
        return self._make_api_request(prompt)

    def _create_function_analysis_prompt(self, func_info: dict) -> str:
        # Create analysis prompt for function naming
        return f"""
Analyze this disassembled function and suggest a meaningful FUNCTION name based on what it actually does.

Current Function Name: {func_info['name']} at Address: {func_info['address']}

Pseudocode (if available):
{func_info.get('pseudocode', 'Not available or not applicable.')}

Assembly (first ~20 instructions):
{func_info.get('assembly', 'Not available.')}

Context Information:
- String References by this function: {', '.join(func_info.get('strings', [])) or 'None'}
- API Calls Made by this function: {', '.join(func_info.get('api_calls', [])) or 'None'}
- Called By (Functions that call this one): {', '.join(func_info.get('xrefs_to', [])) or 'None'}
- Calls To (Functions this one calls): {', '.join(func_info.get('xrefs_from', [])) or 'None'}
- Function Size: {func_info.get('size', 'Unknown')} bytes

Analysis Requirements for FUNCTION name:
1. Use snake_case (e.g., parse_config_data).
2. Be descriptive but concise (max 40 characters).
3. Focus on the primary purpose or action of the entire function.
4. Avoid generic names like 'sub_', 'func_', 'handler', 'process' unless highly specific.
5. If the current name (excluding generic prefixes) is already good, you can state that.

Respond with JSON only:
{{
    "suggested_name": "suggested_function_name_snake_case",
    "confidence": 0.85,
    "reasoning": "Brief explanation of why this name fits the function's overall functionality.",
    "entity_type": "function"
}}
"""

    def _create_local_label_analysis_prompt(self, label_info: dict) -> str:
        # Create analysis prompt for local label naming
        return f"""
Analyze this local code snippet and suggest a meaningful LABEL name for the address {label_info['address']}.
This address is currently named: {label_info['name']}

The address is within the function: {label_info.get('parent_func_name', 'Unknown Function')}
Pseudocode of the parent function (if available, the target address {label_info['address']} might be a jump target within this code):
{label_info.get('parent_func_pseudocode', 'Not available.')}

Local Assembly Context around {label_info['address']} ({LOCAL_ASM_LINES_BEFORE} lines before, {LOCAL_ASM_LINES_AFTER} lines after):
{label_info.get('local_assembly', 'Assembly snippet not available.')}

Context Information for the address {label_info['address']}:
- Cross-references TO this address (where does code jump here from?): {', '.join(label_info.get('xrefs_to_label', [])) or 'None'}
- Notable operands or data used near this address: {', '.join(label_info.get('operands', [])) or 'None'}

Analysis Requirements for LABEL name:
1. Use snake_case, often prefixed by its purpose (e.g., loop_init, error_handler, process_item_block).
2. Be descriptive of what happens AT or FROM this specific address/code block.
3. Keep it concise (max 30 characters).
4. Consider if it's a loop start, error condition, specific data processing step, etc.
5. Avoid overly generic names like 'label', 'loc', 'target'.

Respond with JSON only:
{{
    "suggested_name": "suggested_label_name_snake_case",
    "confidence": 0.75,
    "reasoning": "Brief explanation of why this label name fits the code block starting at this address.",
    "entity_type": "local_label"
}}
"""

    def _parse_response(self, response: str) -> dict:
        # Parse Gem API JSON response
        try:
            clean_response = response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:-3].strip()
            elif clean_response.startswith("```"):
                 clean_response = clean_response[3:-3].strip()

            json_match = re.search(r'\{.*\}', clean_response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group(0))
                if 'suggested_name' in parsed and 'confidence' in parsed and 'entity_type' in parsed:
                    return parsed
                else:
                    logging.error(f"Parsed JSON missing required fields. Parsed: {parsed}")
            else:
                logging.error(f"No JSON object found in response string. Response: {clean_response}")
        except Exception as e:
            logging.error(f"Error parsing Gem API response: {e}")
            logging.debug(f"Raw response from Gem API: {response}")
        return None


class ContextAnalyzer:
    def get_function_details(self, func_ea: int) -> dict:
        func_info = {
            'address': hex(func_ea),
            'name': ida_funcs.get_func_name(func_ea) or f"func_{func_ea:x}",
            'pseudocode': 'Not available',
            'assembly': 'Not available',
            'size': 0,
            'xrefs_to': [],
            'xrefs_from': [],
            'strings': [],
            'api_calls': []
        }
        try:
            func = ida_funcs.get_func(func_ea)
            if not func:
                logging.warning(f"Could not get func object for EA: {hex(func_ea)}")
                return func_info

            func_info['size'] = func.end_ea - func.start_ea
            func_info['pseudocode'] = self._get_pseudocode(func_ea)
            func_info['assembly'] = self._get_assembly_snippet(func.start_ea, func.end_ea, 20)
            func_info['xrefs_to'] = self._get_xrefs_to_ea(func_ea, limit=10, get_func_names=True)
            func_info['xrefs_from'] = self._get_xrefs_from_ea_in_func(func_ea, limit=10, get_func_names=True)
            func_info['strings'] = self._get_string_references_in_func(func_ea, limit=15)
            func_info['api_calls'] = self._get_api_calls_from_func(func_ea, limit=15)
        except Exception as e:
            logging.error(f"Error analyzing function at {hex(func_ea)}: {e}", exc_info=True)
        return func_info

    def get_local_label_details(self, label_ea: int) -> dict:
        label_info = {
            'address': hex(label_ea),
            'name': idc.get_name(label_ea, ida_name.GN_VISIBLE) or f"addr_{label_ea:x}",
            'local_assembly': 'Not available',
            'parent_func_name': 'N/A',
            'parent_func_pseudocode': 'N/A',
            'xrefs_to_label': [],
            'operands': []
        }
        try:
            parent_func = ida_funcs.get_func(label_ea)
            if parent_func:
                label_info['parent_func_name'] = ida_funcs.get_func_name(parent_func.start_ea) or f"func_{parent_func.start_ea:x}"
                label_info['parent_func_pseudocode'] = self._get_pseudocode(parent_func.start_ea)
                label_info['local_assembly'] = self._get_assembly_around_ea(label_ea, parent_func.start_ea, parent_func.end_ea,
                                                                          LOCAL_ASM_LINES_BEFORE, LOCAL_ASM_LINES_AFTER)
            else:
                seg = ida_segment.getseg(label_ea)
                seg_start = seg.start_ea if seg else label_ea - (LOCAL_ASM_LINES_BEFORE * 4)
                seg_end = seg.end_ea if seg else label_ea + (LOCAL_ASM_LINES_AFTER * 15)
                label_info['local_assembly'] = self._get_assembly_around_ea(label_ea, seg_start, seg_end,
                                                                          LOCAL_ASM_LINES_BEFORE, LOCAL_ASM_LINES_AFTER)

            label_info['xrefs_to_label'] = self._get_xrefs_to_ea(label_ea, limit=10, get_func_names=False)
        except Exception as e:
            logging.error(f"Error analyzing local label at {hex(label_ea)}: {e}", exc_info=True)
        return label_info

    def _get_pseudocode(self, func_ea: int) -> str:
        try:
            if not ida_hexrays.init_hexrays_plugin():
                return "Hex-Rays decompiler not available"
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                lines = [ida_lines.tag_remove(sl.line).strip() for sl in cfunc.get_pseudocode() if ida_lines.tag_remove(sl.line).strip()]
                result = '\n'.join(lines)
                return result[:8000] + ("\n... [pseudocode truncated]" if len(result) > 8000 else "") or "Pseudocode generated empty."
            return "Decompilation failed"
        except Exception as e:
            logging.debug(f"Error getting pseudocode for {hex(func_ea)}: {e}")
            return "Error retrieving pseudocode"

    def _get_assembly_snippet(self, start_ea: int, end_ea: int, max_lines: int) -> str:
        lines = []
        curr_ea = start_ea
        for _ in range(max_lines):
            if curr_ea >= end_ea or curr_ea == idaapi.BADADDR:
                break
            disasm = idc.generate_disasm_line(curr_ea, 0)
            if disasm:
                lines.append(f"{hex(curr_ea)}: {disasm}")
            next_ea = idc.next_head(curr_ea, end_ea)
            if next_ea <= curr_ea: break
            curr_ea = next_ea
        return '\n'.join(lines) or "No assembly generated."

    def _get_assembly_around_ea(self, target_ea: int, func_start_ea: int, func_end_ea: int, lines_before: int, lines_after: int) -> str:
        ea_before = target_ea
        actual_lines_before = 0
        for _ in range(lines_before):
            prev_ea = idc.prev_head(ea_before, func_start_ea)
            if prev_ea == idaapi.BADADDR or prev_ea >= ea_before:
                break
            ea_before = prev_ea
            actual_lines_before +=1

        assembly_lines = []
        current_ea = ea_before
        total_lines_to_collect = actual_lines_before + 1 + lines_after

        for i in range(total_lines_to_collect):
            if current_ea == idaapi.BADADDR or current_ea >= func_end_ea:
                break
            
            prefix = ">> " if current_ea == target_ea else "   "
            disasm_line = idc.generate_disasm_line(current_ea, 0)
            if disasm_line:
                assembly_lines.append(f"{prefix}{hex(current_ea)}: {disasm_line}")
            
            next_ea = idc.next_head(current_ea, func_end_ea)
            if next_ea <= current_ea:
                break
            current_ea = next_ea
            
        return '\n'.join(assembly_lines) if assembly_lines else "Could not retrieve assembly."

    def _get_xrefs_to_ea(self, target_ea: int, limit: int = 10, get_func_names: bool = True) -> list:
        xrefs = []
        for xref in idautils.XrefsTo(target_ea, 0):
            if get_func_names:
                caller_func = ida_funcs.get_func(xref.frm)
                if caller_func:
                    name = ida_funcs.get_func_name(caller_func.start_ea) or f"func_{caller_func.start_ea:x}"
                    if name not in xrefs: xrefs.append(name)
                else:
                     if hex(xref.frm) not in xrefs: xrefs.append(hex(xref.frm))
            else:
                if hex(xref.frm) not in xrefs: xrefs.append(hex(xref.frm))

            if len(xrefs) >= limit: break
        return xrefs

    def _get_xrefs_from_ea_in_func(self, func_ea: int, limit: int = 10, get_func_names: bool = True) -> list:
        xrefs = set()
        func = ida_funcs.get_func(func_ea)
        if not func: return []

        for head in idautils.FuncItems(func_ea):
            for xref in idautils.XrefsFrom(head, idaapi.XREF_FAR if idaapi.is_call_insn(head) else idaapi.XREF_DATA):
                if get_func_names:
                    target_func = ida_funcs.get_func(xref.to)
                    if target_func:
                        name = ida_funcs.get_func_name(target_func.start_ea) or f"func_{target_func.start_ea:x}"
                        xrefs.add(name)
                else:
                    xrefs.add(hex(xref.to))
                if len(xrefs) >= limit: break
            if len(xrefs) >= limit: break
        return list(xrefs)

    def _get_string_references_in_func(self, func_ea: int, limit: int = 15) -> list:
        strings = set()
        func = ida_funcs.get_func(func_ea)
        if not func: return []
        try:
            for head in idautils.FuncItems(func_ea):
                for xref in idautils.DataRefsFrom(head):
                    str_type = idc.get_str_type(xref)
                    if str_type is not None and str_type != -1:
                        s = ida_bytes.get_strlit_contents(xref, -1, str_type)
                        if s:
                            decoded_s = s.decode('utf-8', errors='replace') if isinstance(s, bytes) else s
                            if 3 <= len(decoded_s) <= 120: strings.add(decoded_s.strip())
                if len(strings) >= limit: break
            return list(strings)
        except Exception as e:
            logging.error(f"Error getting strings for {hex(func_ea)}: {e}")
            return []

    def _get_api_calls_from_func(self, func_ea: int, limit: int = 15) -> list:
        api_calls = set()
        func = ida_funcs.get_func(func_ea)
        if not func: return []
        try:
            for head in idautils.FuncItems(func_ea):
                for xref in idautils.CodeRefsFrom(head, 0):
                    target_name = ida_funcs.get_func_name(xref.to)
                    if target_name:
                        target_func = ida_funcs.get_func(xref.to)
                        is_import = False
                        if target_func:
                            seg = idaapi.getseg(target_func.start_ea)
                            if seg and (seg.type == idaapi.SEG_XTRN or seg.type == idaapi.SEG_UNDF): is_import = True
                        elif idc.get_full_flags(xref.to) & ida_bytes.FF_IMMOFF: is_import = True
                        
                        if is_import or self._is_common_api_pattern(target_name):
                            api_calls.add(target_name)
                if len(api_calls) >= limit: break
            return list(api_calls)
        except Exception as e:
            logging.error(f"Error getting API calls for {hex(func_ea)}: {e}")
            return []

    def _is_common_api_pattern(self, name: str) -> bool:
        if not name: return False
        win_api_prefixes = ['Create', 'Open', 'Read', 'Write', 'Close', 'Reg', 'Virtual', 'Heap', 'Get', 'Set', 'Find', 'Load', 'Free', 'Is', 'Shell', 'Net', 'WSA', 'Crypt', 'Safe']
        crt_patterns = ['malloc', 'free', 'calloc', 'realloc', 'printf', 'scanf', 'sprintf', 'strcpy', 'strcat', 'strlen', 'strcmp', 'memcpy', 'memset', 'memcmp', 'fopen', 'fclose', 'fread', 'fwrite', 'fprintf', 'fscanf', 'atoi', 'atol', 'strtol', 'exit']
        nix_patterns = [ 'pthread_', 'sem_', 'shm_', 'mq_', 'fork', 'exec', 'pipe', 'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv' ]
        for pattern_list in [win_api_prefixes, crt_patterns, nix_patterns]:
            for p in pattern_list:
                if name.startswith(p): return True
        if name.endswith('A') or name.endswith('W'): return True
        if any(p in name for p in ['Nt', 'Zw', 'Rtl']): return True
        return False


class GenericCalleeVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, context_func_ea):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.generic_callees = {}
        self.context_func_ea = context_func_ea

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        if expr.op == ida_hexrays.cot_call:
            callee_ea = expr.x.obj_ea
            if callee_ea != idaapi.BADADDR and callee_ea != self.context_func_ea:
                callee_name = ida_funcs.get_func_name(callee_ea)
                if callee_name:
                    for prefix in GENERIC_FUNC_PREFIXES:
                        if callee_name.startswith(prefix):
                            if callee_ea not in self.generic_callees:
                                self.generic_callees[callee_ea] = callee_name
                            break
        return 0


# ==================== ACTION HANDLERS ====================

class BaseGemRenamerHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.api_client = GemAPIClient()
        self.analyzer = ContextAnalyzer()

    def _is_valid_ida_name(self, name: str, is_local_label: bool = False) -> bool:
        if not name or not isinstance(name, str): return False
        max_len = 60 if is_local_label else 100
        if len(name) > max_len: return False
        if not re.match(r"^[a-zA-Z_@?$][a-zA-Z0-9_@?$.]*$", name):
             if not is_local_label and not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name):
                return False
        return True

    def _async_api_call_and_handle(self, target_ea: int, original_name: str, context_info: dict, analysis_type: str):
        try:
            logging.info(f"Calling Gem API for {analysis_type}: '{original_name}' ({hex(target_ea)})")
            if analysis_type == "function":
                analysis_result = self.api_client.analyze_function(context_info)
            elif analysis_type == "local_label":
                analysis_result = self.api_client.analyze_local_label(context_info)
            else:
                logging.error(f"Unknown analysis type: {analysis_type}")
                return

            ida_kernwin.execute_ui_requests([partial(self._handle_api_response, target_ea, original_name, analysis_result, analysis_type)])

        except Exception as e:
            logging.error(f"Exception in API call thread for '{original_name}': {e}", exc_info=True)
            error_msg = f"API call thread failed for '{original_name}': {str(e)}"
            ida_kernwin.execute_ui_requests([partial(self._show_error_and_maybe_continue, error_msg)])
            
    def _handle_api_response(self, target_ea: int, original_name: str, analysis: dict, analysis_type: str):
        ida_kernwin.hide_wait_box()
        if not analysis:
            self._show_error_and_maybe_continue(f"Failed to get analysis from Gem for '{original_name}'.")
            return

        suggested_name = analysis.get('suggested_name', '').strip()
        confidence = analysis.get('confidence', 0.0)
        reasoning = analysis.get('reasoning', 'No reasoning provided.').strip()
        
        is_local = (analysis_type == "local_label")
        current_generic_prefixes = GENERIC_LABEL_PREFIXES if is_local else GENERIC_FUNC_PREFIXES

        logging.info(f"Analysis for '{original_name}' ({analysis_type}): Suggested='{suggested_name}', Confidence={confidence:.2f}")

        if not self._is_valid_ida_name(suggested_name, is_local_label=is_local):
            ida_kernwin.warning(f"Invalid name suggested by AI for '{original_name}': '{suggested_name}'. Skipping.")
            self._finalize_item_processing(success=False)
            return

        if suggested_name == original_name or any(suggested_name.startswith(p) for p in current_generic_prefixes):
            ida_kernwin.info(f"AI suggested name '{suggested_name}' for '{original_name}' is same or still generic. Skipping.")
            self._finalize_item_processing(success=False)
            return
        
        self._confirm_and_apply_rename(target_ea, original_name, suggested_name, confidence, reasoning, is_local)

    def _confirm_and_apply_rename(self, target_ea: int, original_name: str, suggested_name: str, confidence: float, reasoning: str, is_local: bool):
        pass

    def _show_error_and_maybe_continue(self, error_msg: str):
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning(error_msg)
        logging.error(f"Error reported to user: {error_msg}")
        self._finalize_item_processing(success=False)

    def _finalize_item_processing(self, success: bool):
        pass


class GemSubFunctionRenamerSelectedHandler(BaseGemRenamerHandler):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        try:
            # Get current view
            vu = ida_hexrays.get_widget_vdui(ctx.widget)
            if not vu:
                ida_kernwin.warning("Unable to get pseudocode view.")
                return

            # Try to get the current function under cursor
            callee_ea = None
            callee_name = None
            
            # Method 1: Try to get from current ctree item
            if vu.item.citype == ida_hexrays.VDI_EXPR and vu.item.e:
                expr = vu.item.e
                if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj:
                    callee_ea = expr.x.obj_ea
            
            # Method 2: If fucking method 1 didn't work, try getting the current line's citem
            if callee_ea is None or callee_ea == idaapi.BADADDR:
                # Get current line number
                line_num = vu.cpos.lnnum
                if line_num >= 0:
                    # Get the ctree items for the current line
                    pc = vu.cfunc.get_pseudocode()
                    if line_num < len(pc):
                        # Try to find a function call in the current line
                        class CallFinder(ida_hexrays.ctree_visitor_t):
                            def __init__(self):
                                ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                                self.calls = []
                            
                            def visit_expr(self, expr):
                                if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj:
                                    self.calls.append(expr.x.obj_ea)
                                return 0
                        
                        finder = CallFinder()
                        finder.apply_to(vu.cfunc.body, None)
                        
                        # Get the current cursor position and try to match with a function name
                        current_word = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
                        if current_word and current_word[1]:
                            highlight_text = current_word[0]
                            # Check if this matches any function name
                            for call_ea in finder.calls:
                                func_name = ida_funcs.get_func_name(call_ea)
                                if func_name and (func_name == highlight_text or highlight_text in func_name):
                                    callee_ea = call_ea
                                    callee_name = func_name
                                    break

            if callee_ea is None or callee_ea == idaapi.BADADDR:
                ida_kernwin.warning("Please place cursor on a function call (e.g., sub_XXXXXX).")
                return

            if not callee_name:
                callee_name = ida_funcs.get_func_name(callee_ea)
            
            if not callee_name:
                ida_kernwin.warning("Cannot determine function name.")
                return

            # Check if it's a generic function
            if not any(callee_name.startswith(p) for p in GENERIC_FUNC_PREFIXES):
                ida_kernwin.warning(f"Function '{callee_name}' is not a generic sub-function.")
                return

            # Process this single function
            ida_kernwin.show_wait_box(f"Analyzing function: '{callee_name}' ({hex(callee_ea)})...\nExtracting info & calling Gem AI...")
            func_details = self.analyzer.get_function_details(callee_ea)
            threading.Thread(target=self._async_api_call_and_handle, args=(callee_ea, callee_name, func_details, "function")).start()

        except Exception as e:
            ida_kernwin.hide_wait_box()
            logging.error(f"Error in GemSubFunctionRenamerSelected activate: {e}", exc_info=True)
            ida_kernwin.warning(f"Error processing selected function: {str(e)}")

    def _confirm_and_apply_rename(self, target_ea: int, original_name: str, suggested_name: str, confidence: float, reasoning: str, is_local: bool):
        message = f"""Gem Analysis for Selected Function:
Original Name:  {original_name} (at {hex(target_ea)})
Suggested Name: {suggested_name}
Confidence:     {confidence:.2f}
Reasoning:
{reasoning}

Apply this rename?"""
        
        apply_rename = ida_kernwin.ask_yn(1 if confidence >= CONFIDENCE_THRESHOLD else 0, message) == 1

        if apply_rename:
            if idc.set_name(target_ea, suggested_name, ida_name.SN_CHECK | ida_name.SN_NON_WEAK):
                ida_kernwin.info(f"Renamed: '{original_name}' → '{suggested_name}'")
                logging.info(f"Renamed '{original_name}' ({hex(target_ea)}) to '{suggested_name}'")
            else:
                current_name = ida_funcs.get_func_name(target_ea)
                if current_name == suggested_name:
                    ida_kernwin.info(f"'{original_name}' is now '{suggested_name}' (name already set/auto-corrected).")
                else:
                    ida_kernwin.warning(f"Failed to rename '{original_name}' to '{suggested_name}'. Current: '{current_name}'.")
                    logging.error(f"Failed to rename '{original_name}' to '{suggested_name}'. Current: '{current_name}' at {hex(target_ea)}")
        else:
            logging.info(f"User declined rename for '{original_name}' to '{suggested_name}'.")
        
        self._finalize_item_processing(success=apply_rename)

    def _finalize_item_processing(self, success: bool):
        ida_kernwin.hide_wait_box()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET


class GemSubFunctionRenamerAllHandler(BaseGemRenamerHandler):
    def __init__(self):
        super().__init__()
        self.pending_callees_to_rename = []
        self.current_callee_index = 0
        self.total_callees_to_process = 0
        self.rename_results = []

    def activate(self, ctx):
        try:
            context_ea = idaapi.get_screen_ea()
            context_func_obj = ida_funcs.get_func(context_ea)
            if not context_func_obj:
                ida_kernwin.warning("Not currently in a function.")
                return
            
            actual_context_ea = context_func_obj.start_ea
            if not ida_hexrays.init_hexrays_plugin():
                ida_kernwin.warning("Hex-Rays decompiler not available.")
                return
            context_cfunc = ida_hexrays.decompile(actual_context_ea)
            if not context_cfunc:
                ida_kernwin.warning(f"Decompilation failed for context function at {hex(actual_context_ea)}.")
                return

            context_func_name = ida_funcs.get_func_name(actual_context_ea) or f"func_{actual_context_ea:x}"
            ida_kernwin.show_wait_box(f"Scanning '{context_func_name}' for sub-functions to rename...")
            
            visitor = GenericCalleeVisitor(actual_context_ea)
            visitor.apply_to(context_cfunc.body, None)
            self.pending_callees_to_rename = list(visitor.generic_callees.items())

            if not self.pending_callees_to_rename:
                ida_kernwin.hide_wait_box()
                ida_kernwin.info(f"No generic sub-functions ({', '.join(GENERIC_FUNC_PREFIXES)}) found called by '{context_func_name}'.")
                return

            # Ask for confirmation before batch processing
            count = len(self.pending_callees_to_rename)
            if ida_kernwin.ask_yn(1, f"Found {count} generic sub-function(s) to rename.\n\nProceed with automatic renaming (no individual confirmations)?") != 1:
                ida_kernwin.hide_wait_box()
                return

            self.current_callee_index = 0
            self.total_callees_to_process = count
            self.rename_results = []
            self._process_next_callee()
        except Exception as e:
            ida_kernwin.hide_wait_box()
            logging.error(f"Error in SubFunctionRenamerAll activate: {e}", exc_info=True)
            ida_kernwin.warning(f"Error scanning for sub-functions: {str(e)}")

    def _process_next_callee(self):
        if self.current_callee_index >= self.total_callees_to_process:
            ida_kernwin.hide_wait_box()
            self._show_batch_results()
            return

        callee_ea, original_callee_name = self.pending_callees_to_rename[self.current_callee_index]
        current_name_check = ida_funcs.get_func_name(callee_ea)
        is_still_generic = current_name_check and any(current_name_check.startswith(p) for p in GENERIC_FUNC_PREFIXES)

        if not is_still_generic:
            logging.info(f"Skipping '{original_callee_name}' ({hex(callee_ea)}), name no longer generic.")
            self.rename_results.append((original_callee_name, hex(callee_ea), "Skipped", "Name no longer generic"))
            self._finalize_item_processing(success=False)
            return
        
        original_callee_name = current_name_check

        ida_kernwin.replace_wait_box(
            f"Processing Sub-Functions ({self.current_callee_index + 1}/{self.total_callees_to_process})\n"
            f"Current: '{original_callee_name}'\n"
            "Calling Gem AI..."
        )
        func_details = self.analyzer.get_function_details(callee_ea)
        threading.Thread(target=self._async_api_call_and_handle, args=(callee_ea, original_callee_name, func_details, "function")).start()

    def _confirm_and_apply_rename(self, target_ea: int, original_name: str, suggested_name: str, confidence: float, reasoning: str, is_local: bool):
        if confidence >= CONFIDENCE_THRESHOLD:
            if idc.set_name(target_ea, suggested_name, ida_name.SN_CHECK | ida_name.SN_NON_WEAK):
                self.rename_results.append((original_name, hex(target_ea), suggested_name, f"Success (confidence: {confidence:.2f})"))
                logging.info(f"Auto-renamed '{original_name}' to '{suggested_name}' (confidence: {confidence:.2f})")
            else:
                current_name = ida_funcs.get_func_name(target_ea)
                if current_name == suggested_name:
                    self.rename_results.append((original_name, hex(target_ea), suggested_name, "Already renamed"))
                else:
                    self.rename_results.append((original_name, hex(target_ea), suggested_name, "Failed to apply"))
                    logging.error(f"Failed to rename '{original_name}' to '{suggested_name}'")
        else:
            self.rename_results.append((original_name, hex(target_ea), suggested_name, f"Skipped (low confidence: {confidence:.2f})"))
            logging.info(f"Skipped '{original_name}' due to low confidence ({confidence:.2f})")
        
        self._finalize_item_processing(success=True)

    def _handle_api_response(self, target_ea: int, original_name: str, analysis: dict, analysis_type: str):
        """Override to handle batch processing without user confirmation"""
        if not analysis:
            self.rename_results.append((original_name, hex(target_ea), "N/A", "API call failed"))
            self._finalize_item_processing(success=False)
            return

        suggested_name = analysis.get('suggested_name', '').strip()
        confidence = analysis.get('confidence', 0.0)
        reasoning = analysis.get('reasoning', 'No reasoning provided.').strip()
        
        is_local = (analysis_type == "local_label")
        current_generic_prefixes = GENERIC_LABEL_PREFIXES if is_local else GENERIC_FUNC_PREFIXES

        logging.info(f"Analysis for '{original_name}': Suggested='{suggested_name}', Confidence={confidence:.2f}")

        if not self._is_valid_ida_name(suggested_name, is_local_label=is_local):
            self.rename_results.append((original_name, hex(target_ea), suggested_name, "Invalid name suggested"))
            self._finalize_item_processing(success=False)
            return

        if suggested_name == original_name or any(suggested_name.startswith(p) for p in current_generic_prefixes):
            self.rename_results.append((original_name, hex(target_ea), suggested_name, "Still generic"))
            self._finalize_item_processing(success=False)
            return
        
        self._confirm_and_apply_rename(target_ea, original_name, suggested_name, confidence, reasoning, is_local)

    def _finalize_item_processing(self, success: bool):
        self.current_callee_index += 1
        ida_kernwin.execute_ui_requests([self._process_next_callee])

    def _show_batch_results(self):
        # Show summary
        success_count = sum(1 for _, _, _, status in self.rename_results if "Success" in status)
        skip_count = sum(1 for _, _, _, status in self.rename_results if "Skipped" in status or "Still generic" in status)
        fail_count = sum(1 for _, _, _, status in self.rename_results if "Failed" in status or "API call failed" in status)
        
        summary = f"Batch Renaming Complete!\n\n"
        summary += f"Total processed: {len(self.rename_results)}\n"
        summary += f"Successfully renamed: {success_count}\n"
        summary += f"Skipped: {skip_count}\n"
        summary += f"Failed: {fail_count}\n\n"
        
        if self.rename_results:
            summary += "Details:\n" + "-"*60 + "\n"
            for orig_name, addr, new_name, status in self.rename_results:
                if "Success" in status:
                    summary += f"✓ {orig_name} → {new_name} ({addr})\n"
                else:
                    summary += f"✗ {orig_name} ({addr}): {status}\n"
        
        ida_kernwin.info(summary)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET


class GemLocalLabelRenamerHandler(BaseGemRenamerHandler):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        try:
            target_ea = ida_kernwin.get_screen_ea()
            if target_ea == idaapi.BADADDR:
                ida_kernwin.warning("Cannot determine current address.")
                return

            original_name = idc.get_name(target_ea, ida_name.GN_VISIBLE) or f"addr_{target_ea:x}"

            ida_kernwin.show_wait_box(f"Analyzing local address: '{original_name}' ({hex(target_ea)})...\nExtracting context & calling Gem AI...")
            
            label_details = self.analyzer.get_local_label_details(target_ea)
            threading.Thread(target=self._async_api_call_and_handle, args=(target_ea, original_name, label_details, "local_label")).start()

        except Exception as e:
            ida_kernwin.hide_wait_box()
            logging.error(f"Error in LocalLabelRenamer activate: {e}", exc_info=True)
            ida_kernwin.warning(f"Error preparing local label for analysis: {str(e)}")

    def _confirm_and_apply_rename(self, target_ea: int, original_name: str, suggested_name: str, confidence: float, reasoning: str, is_local: bool):
        message = f"""Gem Analysis for Local Label:
Original Name:  {original_name} (at {hex(target_ea)})
Suggested Name: {suggested_name}
Confidence:     {confidence:.2f}
Reasoning:
{reasoning}

Apply this rename as a local label?"""
        
        apply_rename = ida_kernwin.ask_yn(1 if confidence >= CONFIDENCE_THRESHOLD else 0, message) == 1

        if apply_rename:
            if idc.set_name(target_ea, suggested_name, ida_name.SN_LOCAL | ida_name.SN_CHECK):
                ida_kernwin.info(f"Renamed local label: '{original_name}' → '{suggested_name}'")
                logging.info(f"Renamed local label '{original_name}' ({hex(target_ea)}) to '{suggested_name}'")
            else:
                current_name = idc.get_name(target_ea, ida_name.GN_VISIBLE)
                if current_name == suggested_name:
                     ida_kernwin.info(f"Local label '{original_name}' is now '{suggested_name}' (name already set/auto-corrected).")
                else:
                    ida_kernwin.warning(f"Failed to rename local label '{original_name}' to '{suggested_name}'. Current: '{current_name}'.")
                    logging.error(f"Failed to rename local label '{original_name}' to '{suggested_name}'. Current: '{current_name}' at {hex(target_ea)}")
        else:
            logging.info(f"User declined rename for local label '{original_name}' to '{suggested_name}'.")
        
        self._finalize_item_processing(success=apply_rename)

    def _finalize_item_processing(self, success: bool):
        ida_kernwin.hide_wait_box()

    def update(self, ctx):
        widget_type = ida_kernwin.get_widget_type(ctx.widget)
        if widget_type == ida_kernwin.BWN_DISASM: 
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


# ==================== PLUGIN REGISTRATION ====================
ACTION_RENAME_SELECTED_FUNC_NAME = 'gem:rename_selected_function'
ACTION_RENAME_SELECTED_FUNC_LABEL = 'Rename Selected Sub-Function'
ACTION_RENAME_SELECTED_FUNC_HOTKEY = 'Ctrl+Shift+G'

ACTION_RENAME_ALL_FUNCS_NAME = 'gem:rename_all_functions'
ACTION_RENAME_ALL_FUNCS_LABEL = 'Rename All Sub-Functions (Batch)'
ACTION_RENAME_ALL_FUNCS_HOTKEY = 'Ctrl+Shift+Alt+G'

ACTION_RENAME_LOCAL_LABEL_NAME = 'gem:rename_local_label'
ACTION_RENAME_LOCAL_LABEL_LABEL = 'Rename Local Label'
ACTION_RENAME_LOCAL_LABEL_HOTKEY = 'Ctrl+Alt+G'

class GemPluginHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RENAME_SELECTED_FUNC_NAME, 'Gem/')
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RENAME_ALL_FUNCS_NAME, 'Gem/')
        elif widget_type == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ACTION_RENAME_LOCAL_LABEL_NAME, 'Gem/')

g_hooks = None
g_registered_actions = []

def register_gem_plugin_actions():
    global g_hooks, g_registered_actions
    
    actions_to_register = [
        (ACTION_RENAME_SELECTED_FUNC_NAME, ACTION_RENAME_SELECTED_FUNC_LABEL, GemSubFunctionRenamerSelectedHandler(), ACTION_RENAME_SELECTED_FUNC_HOTKEY, 'Rename the sub-function under cursor'),
        (ACTION_RENAME_ALL_FUNCS_NAME, ACTION_RENAME_ALL_FUNCS_LABEL, GemSubFunctionRenamerAllHandler(), ACTION_RENAME_ALL_FUNCS_HOTKEY, 'Rename all sub-functions called by current function (batch mode)'),
        (ACTION_RENAME_LOCAL_LABEL_NAME, ACTION_RENAME_LOCAL_LABEL_LABEL, GemLocalLabelRenamerHandler(), ACTION_RENAME_LOCAL_LABEL_HOTKEY, 'Rename local code label/address')
    ]
    
    for name, label, handler, hotkey, tooltip in actions_to_register:
        if name not in g_registered_actions:
            action_desc = ida_kernwin.action_desc_t(name, label, handler, hotkey, tooltip, 199)
            if ida_kernwin.register_action(action_desc):
                logging.info(f"Action '{label}' registered successfully.")
                g_registered_actions.append(name)
            else:
                logging.error(f"Failed to register action '{label}'.")
        else:
            logging.info(f"Action '{label}' already registered.")

    if not g_hooks and idaapi.IDA_SDK_VERSION >= 700:
        g_hooks = GemPluginHooks()
        if g_hooks.hook():
            logging.info("Gem plugin UI hooks installed.")
        else:
            g_hooks = None
            logging.error("Failed to install Gem plugin UI hooks.")

def unregister_gem_plugin_actions():
    global g_hooks, g_registered_actions
    if g_hooks:
        g_hooks.unhook()
        g_hooks = None
        logging.info("Gem plugin UI hooks uninstalled.")
        
    for action_name in list(g_registered_actions):
        if ida_kernwin.unregister_action(action_name):
            logging.info(f"Action '{action_name}' unregistered successfully.")
            g_registered_actions.remove(action_name)

class GemRenamerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Gem AI for renaming functions and local labels"
    help = "Right-click in Pseudocode or Disassembly/Graph views for Gem actions"
    wanted_name = "Gem (Functions & Labels)"
    wanted_hotkey = ""

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            logging.warning("Hex-Rays decompiler not available. Sub-function renaming features may not work.")
        
        register_gem_plugin_actions()
        
        print("="*60)
        print(f"{self.wanted_name} loaded!")
        print(f"   - {ACTION_RENAME_SELECTED_FUNC_LABEL} (Hotkey: {ACTION_RENAME_SELECTED_FUNC_HOTKEY})")
        print(f"   - {ACTION_RENAME_ALL_FUNCS_LABEL} (Hotkey: {ACTION_RENAME_ALL_FUNCS_HOTKEY})")
        print(f"   - {ACTION_RENAME_LOCAL_LABEL_LABEL} (Hotkey: {ACTION_RENAME_LOCAL_LABEL_HOTKEY})")
        if GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
            print("WARNING: Gemini API key is not set in the script!")
        else:
            print(f"Gemini API Key configured (ends with: ...{GEMINI_API_KEY[-4:] if len(GEMINI_API_KEY) > 4 else ''}).")
        print("="*60)
        
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info(f"To use {self.wanted_name}:\n"
                         f"• In Pseudocode view: Right-click for function renaming options\n"
                         f"• In Disassembly view: Right-click for local label renaming\n"
                         f"Or use the hotkeys directly!")

    def term(self):
        unregister_gem_plugin_actions()
        print(f"{self.wanted_name} unloaded.")

def PLUGIN_ENTRY():
    return GemRenamerPlugin()

if __name__ == "__main__":
    try:
        if 'g_plugin_instance' in globals() and g_plugin_instance is not None:
             if hasattr(g_plugin_instance, 'term') and callable(g_plugin_instance.term):
                g_plugin_instance.term()
    except NameError:
        pass
    except Exception as e:
        logging.warning(f"Error during __main__ pre-cleanup: {e}")
    
    temp_action_names = [ACTION_RENAME_SELECTED_FUNC_NAME, ACTION_RENAME_ALL_FUNCS_NAME, ACTION_RENAME_LOCAL_LABEL_NAME]
    for action_name in temp_action_names:
        ida_kernwin.unregister_action(action_name)

    register_gem_plugin_actions()
    logging.info(f"Gem actions registered for script execution.")
    if GEMINI_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
        ida_kernwin.warning("Gemini API key not set in script. Please configure GEMINI_API_KEY.")
