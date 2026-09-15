"""Small interactive shell for the Coeus APK editing workflow.

This file intentionally uses only the Python standard library.  It is useful
with a wheel installed from this repository, for example:

    python coeus-python/coeus_shell.py

The ``python`` command opens a normal Python console with every public
``coeus_python`` object preloaded, plus ``state``, ``apk``, and ``shell``.
Readline/rlcompleter provide Tab completion when available. Leave that
console with Ctrl-D to return to the Coeus prompt.
"""

from __future__ import annotations

import argparse
import cmd
import getpass
import glob
import os
import shlex
from code import InteractiveConsole
from pathlib import Path
from rlcompleter import Completer

try:
    import readline
except ImportError:  # pragma: no cover - Windows may not provide readline
    readline = None

import coeus_python
from coeus_python import SplitApkSet


class CoeusShell(cmd.Cmd):
    intro = "Coeus interactive APK session. Type 'help' for commands."
    prompt = "coeus> "

    def __init__(self, state: SplitApkSet | None = None, adb_path: str | None = None):
        super().__init__()
        self.state = state
        self.adb_path = adb_path
        self.member_index = 0

    @property
    def apk(self):
        if self.state is None:
            raise RuntimeError("load an APK set first")
        return self.state[self.member_index]

    def _args(self, line: str) -> list[str]:
        try:
            return shlex.split(line)
        except ValueError as error:
            print(f"invalid command line: {error}")
            return []

    def _need_state(self) -> bool:
        if self.state is None:
            print("No APK set loaded. Use 'load', 'pull', or 'open'.")
            return False
        return True

    @staticmethod
    def _complete_paths(text: str) -> list[str]:
        """Return readline-friendly completions for a path argument."""
        expanded = os.path.expanduser(text)
        pattern = (expanded or ".") + "*" if expanded else "*"
        completions = []
        for match in glob.glob(pattern):
            path = Path(match)
            value = str(path)
            if path.is_dir():
                value += "/"
            completions.append(value)
        return completions

    def complete_load(self, text: str, line: str, begidx: int, endidx: int):
        return self._complete_paths(text)

    complete_open = complete_load
    complete_write = complete_load
    complete_add = complete_load
    complete_xml = complete_load
    complete_sign = complete_load
    complete_verify = complete_load
    complete_install = complete_load

    def complete_use(self, text: str, line: str, begidx: int, endidx: int):
        if self.state is None:
            return []
        return [str(index) for index in range(len(self.state)) if str(index).startswith(text)]

    def do_load(self, line: str):
        """load APK [APK ...] -- load one base APK or a split set."""
        paths = self._args(line)
        if not paths:
            print("usage: load APK [APK ...]")
            return
        try:
            self.state = SplitApkSet(paths)
            self.member_index = 0
            print(f"loaded {len(self.state)} APK member(s): {self.state.get_names()}")
        except Exception as error:
            print(f"load failed: {error}")

    def do_pull(self, line: str):
        """pull PACKAGE [SERIAL] -- pull base and split APKs from adb."""
        args = self._args(line)
        if not args:
            print("usage: pull PACKAGE [SERIAL]")
            return
        serial = args[1] if len(args) > 1 else None
        try:
            self.state = SplitApkSet.from_adb(args[0], serial, self.adb_path)
            self.member_index = 0
            print(f"pulled {len(self.state)} APK member(s): {self.state.get_names()}")
        except Exception as error:
            print(f"pull failed: {error}")

    def do_list(self, line: str):
        """list [REGEX] [SERIAL] -- list installed package names from adb."""
        args = self._args(line)
        if len(args) > 2:
            print("usage: list [REGEX] [SERIAL]")
            return
        package_regex = args[0] if args else None
        serial = args[1] if len(args) == 2 else None
        try:
            packages = SplitApkSet.list_packages(package_regex, serial, self.adb_path)
            print("\n".join(packages))
            print(f"{len(packages)} package(s)")
        except Exception as error:
            print(f"list failed: {error}")

    def do_open(self, line: str):
        """open STATE -- reload a .coeus save state."""
        args = self._args(line)
        if len(args) != 1:
            print("usage: open STATE")
            return
        try:
            self.state = SplitApkSet.load_state(args[0])
            self.member_index = 0
            print(f"opened {args[0]} ({len(self.state)} APK member(s))")
        except Exception as error:
            print(f"open failed: {error}")

    def do_members(self, line: str):
        """members -- list APK members and the selected member."""
        if not self._need_state():
            return
        for index, name in enumerate(self.state.get_names()):
            marker = " *" if index == self.member_index else ""
            print(f"[{index}] {name}{marker}")

    def do_use(self, line: str):
        """use INDEX -- select the AnalyzeObject used by member-edit commands."""
        args = self._args(line)
        if not self._need_state() or len(args) != 1:
            if self.state is not None and len(args) != 1:
                print("usage: use INDEX")
            return
        try:
            index = int(args[0])
            if index < 0:
                index += len(self.state)
            self.state[index]
            self.member_index = index
            print(f"selected {self.state.get_names()[index]}")
        except (ValueError, IndexError) as error:
            print(f"invalid member: {error}")

    def do_manifest(self, line: str):
        """manifest -- print the selected member's textual AndroidManifest.xml."""
        if self._need_state():
            print(self.apk.get_manifest_xml())

    def do_debuggable(self, line: str):
        """debuggable [on|off] -- set the selected manifest's debuggable flag."""
        args = self._args(line)
        if not self._need_state() or len(args) != 1:
            if self.state is not None:
                print("usage: debuggable on|off")
            return
        try:
            self.apk.set_debuggable(args[0].lower() in {"on", "true", "1"})
            print("updated manifest")
        except Exception as error:
            print(f"manifest edit failed: {error}")

    def do_package(self, line: str):
        """package NAME -- change the selected manifest install identity."""
        args = self._args(line)
        if not self._need_state() or len(args) != 1:
            if self.state is not None:
                print("usage: package NAME")
            return
        try:
            self.apk.set_package_name(args[0])
            print("updated package name")
        except Exception as error:
            print(f"manifest edit failed: {error}")

    def do_plaintext(self, line: str):
        """plaintext -- add Coeus' cleartext/user-CA network configuration."""
        if not self._need_state():
            return
        try:
            self.apk.allow_plaintext_and_user_certificates()
            print("added network-security-config and wired the manifest reference")
        except Exception as error:
            print(f"network configuration failed: {error}")

    def do_add(self, line: str):
        """add APK_PATH ENTRY -- add/replace an APK entry from a local file."""
        args = self._args(line)
        if not self._need_state() or len(args) != 2:
            if self.state is not None:
                print("usage: add APK_PATH ENTRY")
            return
        try:
            self.apk.set_file(args[1], Path(args[0]).read_bytes())
            print(f"added {args[1]}")
        except Exception as error:
            print(f"file edit failed: {error}")

    def do_xml(self, line: str):
        """xml ENTRY XML_PATH -- replace an XML resource from a text file."""
        args = self._args(line)
        if not self._need_state() or len(args) != 2:
            if self.state is not None:
                print("usage: xml ENTRY XML_PATH")
            return
        try:
            self.apk.set_xml_resource(args[0], Path(args[1]).read_text())
            print(f"updated {args[0]}")
        except Exception as error:
            print(f"XML edit failed: {error}")

    def do_save(self, line: str):
        """save STATE -- save current unsigned members and edit history."""
        args = self._args(line)
        if not self._need_state() or len(args) != 1:
            if self.state is not None:
                print("usage: save STATE")
            return
        try:
            self.state.save_state(args[0])
            print(f"saved {args[0]}")
        except Exception as error:
            print(f"save failed: {error}")

    def do_write(self, line: str):
        """write DIRECTORY -- repack all current members without signing."""
        args = self._args(line)
        if not self._need_state() or len(args) != 1:
            if self.state is not None:
                print("usage: write DIRECTORY")
            return
        try:
            print("\n".join(self.state.write_all(args[0])))
        except Exception as error:
            print(f"write failed: {error}")

    def do_sign(self, line: str):
        """sign DIRECTORY KEYSTORE ALIAS -- repack and sign all members."""
        args = self._args(line)
        if not self._need_state() or len(args) != 3:
            if self.state is not None:
                print("usage: sign DIRECTORY KEYSTORE ALIAS")
            return
        store_password = getpass.getpass("keystore password: ")
        key_password = getpass.getpass("key password (empty uses keystore password): ")
        try:
            paths = self.state.sign_all(
                args[0], args[1], args[2], store_password, key_password or None
            )
            print("\n".join(paths))
        except Exception as error:
            print(f"sign failed: {error}")

    def do_verify(self, line: str):
        """verify DIRECTORY [APKSIGNER] -- verify all signed members."""
        args = self._args(line)
        if not self._need_state() or not (1 <= len(args) <= 2):
            if self.state is not None:
                print("usage: verify DIRECTORY [APKSIGNER]")
            return
        try:
            result = self.state.verify_all(args[0], args[1] if len(args) == 2 else None)
            print("\n---\n".join(result))
        except Exception as error:
            print(f"verify failed: {error}")

    def do_install(self, line: str):
        """install DIRECTORY [SERIAL] -- install the signed split set with adb."""
        args = self._args(line)
        if not self._need_state() or not (1 <= len(args) <= 2):
            if self.state is not None:
                print("usage: install DIRECTORY [SERIAL]")
            return
        try:
            print(self.state.install_all(args[0], args[1] if len(args) == 2 else None, self.adb_path))
        except Exception as error:
            print(f"install failed: {error}")

    def do_launch(self, line: str):
        """launch PACKAGE [SERIAL] -- start the installed package with adb."""
        args = self._args(line)
        if not args or len(args) > 2:
            print("usage: launch PACKAGE [SERIAL]")
            return
        if not self._need_state():
            return
        try:
            print(self.state.launch(args[0], args[1] if len(args) == 2 else None, self.adb_path))
        except Exception as error:
            print(f"launch failed: {error}")

    def do_history(self, line: str):
        """history -- show recorded high-level edits and lifecycle actions."""
        if self._need_state():
            print("\n".join(self.state.get_history()))

    def do_python(self, line: str):
        """python -- open a console with all public Coeus objects preloaded."""
        namespace = {
            name: value
            for name, value in vars(coeus_python).items()
            if not name.startswith("_")
        }
        namespace.update(
            state=self.state,
            apk=self.apk if self.state else None,
            shell=self,
            coeus_python=coeus_python,
        )
        console = InteractiveConsole(namespace)
        if readline is None:
            console.interact(
                "Coeus objects are preloaded; use state, apk, and shell. "
                "Leave with exit() or Ctrl-D."
            )
            return

        old_completer = readline.get_completer()
        old_delims = readline.get_completer_delims()
        try:
            readline.set_completer(Completer(namespace).complete)
            readline.set_completer_delims(" \t\n`~!@#$%^&*()-=+[{]}\\|;:'\",<>/?")
            readline.parse_and_bind("tab: complete")
            console.interact(
                "Tab completion enabled. Coeus objects are preloaded; use state, "
                "apk, and shell. Leave with exit() or Ctrl-D."
            )
        finally:
            readline.set_completer(old_completer)
            readline.set_completer_delims(old_delims)

    def do_quit(self, line: str):
        """quit -- leave the interactive session."""
        return True

    do_exit = do_quit


def main() -> None:
    parser = argparse.ArgumentParser(description="Interactive Coeus APK editor")
    parser.add_argument("paths", nargs="*", help="APK paths to load initially")
    parser.add_argument("--state", help="open a .coeus state initially")
    parser.add_argument("--package", help="pull an installed package initially")
    parser.add_argument("--serial", help="adb device serial")
    parser.add_argument("--adb", dest="adb_path", help="adb executable path")
    args = parser.parse_args()

    try:
        if args.state:
            state = SplitApkSet.load_state(args.state)
        elif args.package:
            state = SplitApkSet.from_adb(args.package, args.serial, args.adb_path)
        elif args.paths:
            state = SplitApkSet(args.paths)
        else:
            state = None
    except Exception as error:
        parser.error(str(error))

    shell = CoeusShell(state, args.adb_path)
    shell.cmdloop()


if __name__ == "__main__":
    main()
