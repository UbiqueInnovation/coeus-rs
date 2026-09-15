# Copyright (c) 2023 Ubique Innovation AG <https://www.ubique.ch>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

maturin build --release --out dist --sdist
maturin build --release --target x86_64-apple-darwin --out dist --sdist
ZIG_COMMAND=zig maturin build --release --target x86_64-pc-windows-msvc --out dist --sdist
maturin build --release --target x86_64-unknown-linux-gnu --out dist --sdist
maturin build --release --target aarch64-unknown-linux-gnu --out dist --sdist
