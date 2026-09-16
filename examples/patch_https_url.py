#!/usr/bin/env python3
"""Patch the swiyu APK so its HTTPS URL check succeeds for test URLs.

The Android implementation of URLUtil.isHttpsUrl() is not part of the APK.
Therefore this redirects the result at the APK call site instead of trying to
add/replace android.webkit.URLUtil.
"""

from pathlib import Path
import sys

from coeus_python import AnalyzeObject, DexInstruction


DEFAULT_INPUT = Path(
    "/tmp/test-coeus/swiyu/SwiyuWallet-sandbox_1.18.0-1296.apk"
)
DEFAULT_OUTPUT = Path(
    "/tmp/test-coeus/swiyu/SwiyuWallet-sandbox_1.18.0-1296-http-patched.apk"
)

URL_UTIL_CALL = (
    "Landroid/webkit/URLUtil;->isHttpsUrl(Ljava/lang/String;)Z"
)


def patch_https_check(apk: AnalyzeObject) -> int:
    """Replace every in-app URLUtil.isHttpsUrl call with `true`.

    The known call uses p1 for the boolean result. `const` (const/32) is
    three code units, matching the width of invoke-static. The following
    move-result is one code unit, matching nop.
    """

    patches = []
    for clazz in apk.get_classes_as_class():
        for method in clazz.get_methods():
            instructions = method.get_instructions()
            for index, instruction in enumerate(instructions):
                if URL_UTIL_CALL not in str(instruction):
                    continue

                if index + 1 >= len(instructions):
                    raise RuntimeError(
                        f"isHttpsUrl call has no following result instruction in "
                        f"{method.signature()}"
                    )

                result = instructions[index + 1]
                if result.mnemonic() != "move-result":
                    raise RuntimeError(
                        f"unexpected result instruction {result.mnemonic()} in "
                        f"{method.signature()}"
                    )

                # The swiyu call site stores the result in p1. Both
                # replacements preserve the original instruction widths.
                replacement_call = DexInstruction.const_lit32(1, 1)
                replacement_result = DexInstruction.nop()
                if replacement_call.get_size() != instruction.get_size():
                    raise RuntimeError("replacement does not match invoke width")
                if replacement_result.get_size() != result.get_size():
                    raise RuntimeError("replacement does not match move-result width")

                patches.append((method, instruction, replacement_call))
                patches.append((method, result, replacement_result))

    if not patches:
        raise RuntimeError(f"Could not find {URL_UTIL_CALL} in the APK")

    # Apply in discovery order. Coeus reparses the edited DEX after each
    # operation, but offsets and widths remain stable because replacements are
    # same-width.
    for method, instruction, replacement in patches:
        apk.replace_instruction(method, instruction, replacement)

    return len(patches) // 2


def main() -> None:
    input_apk = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output_apk = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT

    apk = AnalyzeObject(str(input_apk), False, -1)
    count = patch_https_check(apk)
    apk.write_apk(str(output_apk))
    print(f"Patched {count} isHttpsUrl call(s)")
    print(f"Wrote unsigned APK: {output_apk}")


if __name__ == "__main__":
    main()
