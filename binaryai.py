# Load analysis result from binaryai.net,
# BinaryAI is a binary file security analysis platform developed by Tencent Security Keen Lab.
# Copyright 2021-2023 Tencent. All Rights Reserved.

#@author Tencent Security KeenLab
#@category Binary

from __future__ import unicode_literals
import platform
import os
import json
import re
import io

ENV = None
if platform.python_implementation() == "Jython":
    # import ghidra dependency
    import ghidra
    from ghidra.util import Msg
    from javax.swing import JFrame, JTextArea, WindowConstants, JPanel, JScrollPane, JTextPane
    from java.awt import BorderLayout, Dimension, Insets
    from urlparse import urlparse

    ENV = "GHIDRA"
else:
    import ida_kernwin
    import idaapi
    import ida_nalt
    try:
        from pygments.lexers import CppLexer
        from pygments.token import Token
    except Exception:
        # Missing library is managed at the plugin entry
        pass
    if platform.python_version().startswith("2"):
        from urlparse import urlparse
    elif platform.python_version().startswith("3"):
        from urllib.parse import urlparse
    ENV = "IDA"


try:
    from ghidra.ghidra_builtins import *
except:
    pass

IMPORT_ERROR_TITLE = "Import Error"
FORMAT_PATTERN = r"^(https?)://((?:www.)?(?:{}))/([^/]+?)/([^/]+?)(?:.git)?/?$"
repoUrlPolicy = [
    {'pathSeparator': 'tree', 'regexp': FORMAT_PATTERN.format('github.com')},
    {'pathSeparator': '-/tree', 'regexp': FORMAT_PATTERN.format('salsa.debian.org|gitlab.gnome.org|gitlab.com')},
    {'pathSeparator': 'src', 'regexp': FORMAT_PATTERN.format('bitbucket.org')},
]


class Utils:

    @staticmethod
    def is_ida_version_supported():
        if idaapi.IDA_SDK_VERSION > 730:
            return True
        print("IDA version should be at least 7.3")
        return False

    @staticmethod
    def get_source_location(repoUrl, version):
        for policy in repoUrlPolicy:
            matched = re.match(policy['regexp'], repoUrl)
            if not matched or len(matched.groups()) != 4:
                continue
            return "{0}://{1}/{2}/{3}/{pathSep}/{version}".format(
                matched.group(1),
                matched.group(2),
                matched.group(3),
                matched.group(4),
                pathSep=policy['pathSeparator'],
                version=version
            )
        return None

    @staticmethod
    def should_ends_with_l_anchor(host):
        return host in ['github.com', 'gitlab.com', 'gitlab.gnome.org', 'salsa.debian.org']

    @staticmethod
    def should_ends_with_line_anchor(host):
        return host in ['bitbucket.org']

    @staticmethod
    def get_source_location_with_line(repoUrl, version, filepath, line):
        url = urlparse(repoUrl)
        code_location = Utils.get_source_location(repoUrl, version)
        raw_path_with_line = "{}#L{}".format(filepath, line)
        if not code_location:
            return raw_path_with_line
        if Utils.should_ends_with_l_anchor(url.hostname):
            code_location_with_line = "{}/{}#L{}".format(code_location, filepath, line)
        elif Utils.should_ends_with_line_anchor(url.hostname):
            code_location_with_line = "{}/{}#line-{}".format(code_location, filepath, line)
        else:
            code_location_with_line = raw_path_with_line
        return code_location_with_line


# ------------------------------------------------------------
#   GHIDRA Script
# ------------------------------------------------------------

class GhidraScript:

    def __init__(self):
        self.frame = None
        self.functions = {}
        self.base_addr = None
        self.current_function = None

    def setup_ui(self):
        self.frame = JFrame("BinaryAI")

        self.panel = JPanel()
        self.panel.setLayout(BorderLayout(0, 0))
        self.panel.setPreferredSize(Dimension(600, 600))

        self.scrollPane = JScrollPane()
        self.panel.add(self.scrollPane, BorderLayout.CENTER)
        self.codePane = JTextPane()
        self.scrollPane.setViewportView(self.codePane)
        self.infoPane = JTextPane()
        self.infoPane.setPreferredSize(Dimension(600, 120))
        self.infoPane.setMargin(Insets(0, 10, 10, 10))
        self.infoPane.setText("Click on function to see result.")
        self.panel.add(self.infoPane, BorderLayout.NORTH)

        self.frame.add(self.panel)
        self.frame.pack()

        self.frame.setLocationRelativeTo(None)
        self.frame.setAlwaysOnTop(True)
        self.frame.setVisible(True)

    def load_json(self):
        fp = askFile("Please choose the json file downloaded from binaryai.net", "Confirm")
        fp = str(fp)
        if not os.path.exists(fp):
            Msg.showError(self, None, IMPORT_ERROR_TITLE, "{} does not exists.".format(fp))
            return False
        with io.open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
        sha256 = currentProgram.getExecutableSHA256()
        if 'file_sha256' not in data or data['file_sha256'] != sha256:
            Msg.showError(self, None, IMPORT_ERROR_TITLE, "json file does not match the binary.")
            return False
        if 'base_addr' not in data:
            Msg.showError(self, None, IMPORT_ERROR_TITLE, "Could not found base address in json file.")
            return False

        self.base_addr = data['base_addr']
        currentProgram.setImageBase(toAddr(self.base_addr), True)
        if 'functions' not in data:
            Msg.showError(self, None, IMPORT_ERROR_TITLE, "Could not found functions in json file.")
        for addr, item in data['functions'].iteritems():
            self.functions[int(addr)] = item
        return True

    def update_info(self, func, addr):
        url = Utils.get_source_location_with_line(func['entry_url'], func['slot_name'], func['filepath'],
                                                  func['line_number'])
        comment = "Function Entry: {}\n".format(addr)
        comment += "Function Name: {}\n".format(func['function_name'])
        comment += "Score: {}\n".format(func['score'])
        comment += "Git URL: {}\n".format(func['entry_url'])
        comment += "Version: {}\n".format(func['slot_name'])
        comment += "Source file path: {}\n".format(url)
        self.infoPane.setText(comment)

    def update_code(self, func):
        self.codePane.setText(func['code'])
        self.codePane.setCaretPosition(0);

    def register(self):
        code_viewer = state.getTool().getService(ghidra.app.services.CodeViewerService)

        class MyListener(ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener):
            def __init__(self, script):
                self.script = script

            def visibleAddressesChanged(self, visibleAddresses):

                if visibleAddresses is None or visibleAddresses.minAddress is None:
                    return

                function = getFunctionContaining(visibleAddresses.minAddress)
                if function and function.getEntryPoint().getOffset() in self.script.functions:
                    func = self.script.functions[function.getEntryPoint().getOffset()]
                    self.script.update_code(func)
                    self.script.update_info(func, function.getEntryPoint())
                else:
                    self.script.infoPane.setText("Not Found.")
                    self.script.codePane.setText("")

        if not state.getEnvironmentVar("BINARYAI_INITED"):
            code_viewer.addListingDisplayListener(MyListener(self))
            state.addEnvironmentVar("BINARYAI_INITED", True)

    def add_bookmarks(self):
        idx = 0
        total = len(self.functions)
        monitor.initialize(total)
        for addr, func in self.functions.iteritems():
            monitor.checkCanceled()
            # print("===== {:#x} {} {}".format(addr, func['function_name'], func['score']))
            createBookmark(toAddr(addr), "BinaryAI", "{}".format(func['function_name']))
            monitor.incrementProgress(1)
            monitor.setMessage("Working on {}/{}".format(idx, total))
            idx += 1

        Msg.showInfo(self, None, "Success!", "Annotate {} functions.".format(len(self.functions)))

    def run(self):
        if not self.load_json():
            return
        self.setup_ui()
        self.add_bookmarks()
        self.register()
        self.frame.show()

if __name__ == "__main__":
    if ENV == "GHIDRA":
        script = GhidraScript()
        script.run()
        exit(0)

# ------------------------------------------------------------
#   IDA Plugin
# ------------------------------------------------------------

class Viewer(object):

    class InfoViewerUI(idaapi.simplecustviewer_t):
        def __init__(self, title):
            idaapi.simplecustviewer_t.__init__(self)
            self.title = title
            self.text = ""
            self.Create(title)

        def _repaint(self):
            self.ClearLines()
            for line in self.text.splitlines():
                self.AddLine(line)
            self.Refresh()

        def update(self, text):
            self.text = text
            self._repaint()

        def dock(self):
            idaapi.set_dock_pos(self.title, "Output window", idaapi.DP_RIGHT)

    class SourceCodeViewerUI(idaapi.simplecustviewer_t):
        def __init__(self, title):
            idaapi.simplecustviewer_t.__init__(self)
            self.title = title
            self.Create(title)
            self.code = None
            idaapi.set_code_viewer_is_source(idaapi.create_code_viewer(self.GetWidget(), 0x4))

        def color_line(self, code):
            """
            """
            lexer = CppLexer()
            tokens = list(lexer.get_tokens(code))
            new_line = ""
            for t in tokens:
                ttype = t[0]
                ttext = str(t[1])
                if ttype == Token.Text:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_INSN)

                elif ttype == Token.Text.Whitespace:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_INSN)

                elif ttype == Token.Error:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_ERROR)

                elif ttype == Token.Other:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DSTR)

                elif ttype == Token.Keyword:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_KEYWORD)

                elif ttype == Token.Keyword.Type:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_LOCNAME)

                elif ttype == Token.Name:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DEFAULT)

                elif ttype == Token.Name.Class:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DNAME)

                elif ttype == Token.Name.Constant:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DSTR)

                elif ttype == Token.Name.Builtin:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DEFAULT)

                elif ttype == Token.Literal:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_LOCNAME)

                elif ttype in Token.Literal.String:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_STRING)

                elif ttype in Token.Literal.Number:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DNUM)

                elif ttype == Token.Operator:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_ALTOP)

                elif ttype == Token.Punctuation:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_SYMBOL)

                elif ttype in Token.Comment:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_REGCMT)

                elif ttype == Token.Generic:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_CREFTAIL)

                else:
                    new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_CREFTAIL)
            return new_line

        def update(self, code):
            self.code = code
            self._repaint()

        def _repaint(self):
            self.ClearLines()
            for line in self.code.splitlines():
                line = self.color_line(line)
                self.AddLine(line)
            self.Refresh()

        def dock(self, widget):
            title = idaapi.get_widget_title(widget)
            idaapi.set_dock_pos(self.title, title, idaapi.DP_RIGHT)

    def __init__(self):
        self.code_view = None # Viewer.SourceCodeViewerUI
        self.info_view = None # Viewer.InfoViewerUI
        self.visible = False

    def reset(self):
        if self.code_view is not None:
            ida_kernwin.close_widget(self.code_view.GetWidget(), 0)
        if self.info_view is not None:
            ida_kernwin.close_widget(self.info_view.GetWidget(), 0)
        self.code_view = None
        self.info_view = None
        self.visible = False

    def is_visible(self):
        return self.code_view and self.code_view.GetWidget()

    def update(self, func):
        if func is None:
            self.reset()
            return
        else:
            code = func['code']
            url = Utils.get_source_location_with_line(func['entry_url'], func['slot_name'], func['filepath'],
                                                      func['line_number'])
            info = "Function Name:    {}\n".format(idaapi.COLSTR(func['function_name'], idaapi.SCOLOR_LIBNAME))
            info += "Score:            {}\n".format(idaapi.COLSTR(str(func['score']), idaapi.SCOLOR_LIBNAME))
            info += "Git URL:          {}\n".format(idaapi.COLSTR(func['entry_url'], idaapi.SCOLOR_LIBNAME))
            info += "Version:          {}\n".format(idaapi.COLSTR(func['slot_name'], idaapi.SCOLOR_LIBNAME))
            info += "Source file path: {}\n".format(idaapi.COLSTR(url, idaapi.SCOLOR_LIBNAME))
        first_time = False
        if not self.is_visible():
            self.code_view = Viewer.SourceCodeViewerUI("BinaryAI Matched Source")
            self.info_view = Viewer.InfoViewerUI("BinaryAI Function metadata")
            first_time = True
        widget = idaapi.get_current_widget()
        self.code_view.update(code)
        self.info_view.update(info)
        if first_time:
            self.code_view.Show()
            self.info_view.Show()
            self.code_view.dock(widget)
            self.info_view.dock()


class UIHooks(idaapi.UI_Hooks):

    HIGHLIGHT_COLOR = 0x95DE64

    def __init__(self, plugin):
        ida_kernwin.UI_Hooks.__init__(self)
        self.plugin = plugin
        self.is_function_window_hooked = False
        self.current_func = None

    def get_chooser_item_attrs(self, chooser, n, attrs):
        func = idaapi.getn_func(n)
        if self.plugin.function_dict and func.start_ea in self.plugin.function_dict:
            attrs.color = self.HIGHLIGHT_COLOR

    def updating_actions(self, ctx):
        title = None
        if idaapi.find_widget("Functions"): # >= version 7.7
            title = "Functions"
        elif idaapi.find_widget("Functions window"):
            title = "Functions window"
        if not self.is_function_window_hooked and title:
            self.is_function_window_hooked = idaapi.enable_chooser_item_attrs(title, True)

    def screen_ea_changed(self, ea, prev_ea):
        if self.plugin.viewer is None:
            return
        func = idaapi.get_func(ea)
        if func and func.start_ea in self.plugin.function_dict:
            if self.current_func != func:
                f = self.plugin.function_dict[func.start_ea]
                self.plugin.viewer.update(f)
                self.current_func = func
        else:
            self.plugin.viewer.reset()

class IDAPlugin(idaapi.plugin_t):
    comment = "BinaryAI plugin for IDA Pro"
    help = "BinaryAI plugin shortcut key is Ctrl-Shift-B"
    wanted_name = "BinaryAI"
    wanted_hotkey = "Ctrl-Shift-B"
    # flags = idaapi.PLUGIN_UNL
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        print("#" * 60)
        print("https://github.com/binaryai/plugins")
        print("BinaryAI plugin shortcut key is Ctrl-Shift-B")
        self.viewer = None
        self.function_dict = None
        self.ui_hooks = UIHooks(self)
        self.ui_hooks.hook()
        return idaapi.PLUGIN_KEEP

    def term(self):
        self.ui_hooks.unhook()
        return

    def to_ida_addr(self, addr):
        return (addr - self.base_addr) + self.ida_base_addr

    def load_json(self):
        fp = ida_kernwin.ask_file(False, "*.json", "file download from binaryai.net")
        if not fp:
            return False
        if not os.path.exists(fp):
            ida_kernwin.warning("file does not exists.")
            return False
        with io.open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)

        if 'base_addr' not in data or 'functions' not in data:
            ida_kernwin.warning("json format error.")
            return False

        sha256 = ida_nalt.retrieve_input_file_sha256().hex()
        if 'file_sha256' not in data or data['file_sha256'] != sha256:
            ida_kernwin.warning("json file does not match the binary.")
            return False

        self.base_addr = data['base_addr']
        self.ida_base_addr = idaapi.get_imagebase()
        self.function_dict = {self.to_ida_addr(int(addr)): func for addr, func in data['functions'].items()}
        ida_kernwin.info("Matches {} functions.".format(len(self.function_dict)))
        return True

    def run(self, arg):
        if not self.load_json():
            return
        if self.viewer is None:
            self.viewer = Viewer()
        else:
            self.viewer.reset()
        self.ui_hooks.is_function_window_hooked = False

        # Rename functions in IDB
        _rename_choice = ida_kernwin.ask_buttons(
            "Yes", "No", "Cancel", 2, "Do you want to rename all matched functions in the IDB?")
        if _rename_choice == 1:
            _function_set = {}
            for _addr, _func in self.function_dict.items():
                #print(hex(_addr), _func["function_name"])
                _func_name = _func["function_name"]
                _func_name = _func_name if _function_set.get(
                    _func_name) is None else _func_name + "_" + str(_function_set.get(_func_name))
                idaapi.set_name(_addr, _func_name)
                _function_set[_func_name] = 0 if _function_set.get(
                    _func_name) is None else _function_set[_func_name] + 1
            del _function_set


def PLUGIN_ENTRY():
    if not Utils.is_ida_version_supported():
        return idaapi.PLUGIN_SKIP
    try:
        import pygments
    except Exception:
        print("BinaryAI: pygments library is missing")
        print("pip install pygments")
        return idaapi.PLUGIN_SKIP
    return IDAPlugin()
